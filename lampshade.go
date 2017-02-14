// Package lampshade provides a transport between Lantern clients and proxies
// that provides obfuscated encryption as well as multiplexing. The protocol
// attempts to be indistinguishable in content and timing from a random stream
// of bytes, and mostly follows the OBFS4 threat model -
// https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt#L35
//
// Lampshade attempts to minimize overhead, so it uses less padding than OBFS4.
// Also, to avoid having to pad at all, lampshade coalesces consecutive small
// writes into single larger messages when there are multiple pending writes.
// Due to lampshade being multiplexed, especially during periods of high
// activity, coalescing is often possible.
//
// Note - lampshade does not ensure message integrity and authenticity, it
// simply encrypts in order to obfuscate the real content of a data stream.
// Applications running over lampshade should continue to use TLS or other
// mechanisms to ensure full integrity, authenticity and confidentiality.
//
// Definitions:
//
//   physical connection - an underlying (e.g. TCP) connection
//
//   stream              - a virtual connection multiplexed over a physical
//                         connection
//
//   session             - unit for managing multiplexed streams, corresponds
//                         1 to 1 with a physical connection
//
// Protocol:
//
//   Seession initiation
//
//      client --> client init --> server
//
//   Write
//
//      client --> frame --> server
//      client --> frame --> server
//      client --> frame --> server
//      ... continue up to transmit window
//      client <--  ack  <-- server
//      client --> frame --> server
//      client <--  ack  <-- server
//      client <--  ack  <-- server
//      client --> frame --> server
//      client --> frame --> server
//      ... etc ...
//
//   Read (parallel to write)
//
//      client <-- frame <-- server
//      client <-- frame <-- server
//      client <-- frame <-- server
//      ... continue up to transmit window
//      client -->  ack  --> server
//      client <-- frame <-- server
//      client -->  ack  --> server
//      client -->  ack  --> server
//      client <-- frame <-- server
//      client <-- frame <-- server
//      ... etc ...
//
// General Protocol Features
//
//   - protocol attempts to be indistinguishable in content and timing from a
//     random stream of bytes, following the OBFS4 threat model -
//     https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt#L35
//
//   - all numeric fields are unsigned integers in BigEndian format
//
// Client Init Message
//
//   256 bytes, always combined with first data message to vary size.
//
//   To initialize a session, the client sends the below, encrypted using
//   RSA OAEP using the server's PK:
//
//     +---------+-----+---------+--------+--------+---------+---------+
//     | Version | Win | Max Pad | Cipher | Secret | Send IV | Recv IV |
//     +---------+-----+---------+--------+--------+---------+---------+
//     |    1    |  4  |    1    |    1   | 16/32  |  16/12  |  16/12  |
//     +---------+-----+---------+--------+--------+---------+---------+
//
//       Version - the version of the protocol (currently 1)
//
//       Win     - transmit window size in # of frames
//
//       Max Pad - maximum random padding
//
//       Cipher  - 1 = None, 2 = AES128_CTR, 3 = ChaCha20
//
//       Secret  - 128 bits of secret for AES128_CTR, 256 bits for ChaCha20
//
//       Send IV - initialization vector for messages from client -> server,
//                 128 bits for AES_CTR, 96 bits for ChaCha20
//
//       Recv IV - initialization vector for messages from server -> client,
//                 128 bits for AES_CTR, 96 bits for ChaCha20
//
// Framing:
//
//   All frames are encrypted with AES128 in CTR mode, using the secret and IV
//   sent in the Init Session message.
//
//     +--------------+-----------+----------+--------+
//     |              |           | Data Len |        |
//     | Message Type | Stream ID | / Frames |  Data  |
//     +--------------+-----------+----------+--------+
//     |      1       |     2     |    2/4   | <=1443 |
//     +--------------+-----------+----------+--------+
//
//     Message Type - indicates the message type.
//
//       0 = data
//       1 = padding
//       2 = ack
//       3 = rst (close connection)
//
//     Stream ID - unique identifier for stream. (last field for ack and rst)
//
//     Data Len - length of data (for type "data" or "padding")
//
//     Frames   - number of frames being ACK'd (for type ACK)
//
//     Data     - data (for type "data" or "padding")
//
// Padding:
//
//   - used only when there weren't enough pending writes to coalesce
//   - size varies randomly based on max pad parameter in init message
//   - looks just like a standard frame, with empty data
//   - the "empty" data actually looks random on the wire since it's being
//     encrypted with a stream cipher.
//
// Flow Control:
//
//   Flow control is managed with windows similarly to HTTP/2.
//
//     - windows are sized based on # of frames rather than # of bytes
//     - both ends of a stream maintain a transmit window
//     - the window is initialized based on the win parameter in the client
//       init message
//     - as the sender transmits data, its transmit window decreases by the
//       number of frames sent (not including headers)
//     - if the sender's transmit window reaches 0, it stalls
//     - as the receiver's buffers free up, it sends ACKs to the sender that
//       instruct it to increase its transmit window by a given amount
//     - blocked senders become unblocked when their transmit window exceeds 0
//       again
//     - if the client requests a window larger than what the server is willing
//       to buffer, the server can adjust the window by sending an ACK with a
//       negative value
//
package lampshade

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/getlantern/golog"
	"github.com/oxtoacart/bpool"
)

const (
	// client init message
	clientInitSize = 256
	versionSize    = 1
	winSize        = 4
	maxPaddingSize = 1

	protocolVersion1 = 1

	// NoEncryption is no encryption
	NoEncryption = 1
	// AES128CTR is 128-bit AES in CTR mode
	AES128CTR = 2
	// ChaCha20 is 256-bit ChaCha20 with a 96-bit Nonce
	ChaCha20 = 3

	// framing
	headerSize     = 3
	lenSize        = 2
	dataHeaderSize = headerSize + lenSize

	maxFrameSize = coalesceThreshold
	ackFrameSize = headerSize + winSize

	// MaxDataLen is the maximum length of data in a lampshade frame.
	MaxDataLen = maxFrameSize - dataHeaderSize

	// frame types
	frameTypeData    = 0
	frameTypePadding = 1
	frameTypeACK     = 2
	frameTypeRST     = 3

	ackRatio          = 10 // ack every 1/10 of window
	defaultWindowSize = 2 * 1024 * 1024 / MaxDataLen
	maxID             = (2 << 15) - 1

	coalesceThreshold = 1448 // basically this is the practical TCP MSS for anything traversing Ethernet and using TCP timestamps
)

var (
	log = golog.LoggerFor("lampshade")

	// ErrTimeout indicates that an i/o operation timed out.
	ErrTimeout = &netError{"i/o timeout", true, true}
	// ErrConnectionClosed indicates that an i/o operation was attempted on a
	// closed stream.
	ErrConnectionClosed = &netError{"connection closed", false, false}
	// ErrBrokenPipe indicates that an i/o operation was attempted on session
	// whose underlying connection isn't working anymore.
	ErrBrokenPipe = &netError{"broken pipe", false, false}
	// ErrListenerClosed indicates that an Accept was attempted on a closed
	// listener.
	ErrListenerClosed = &netError{"listener closed", false, false}

	binaryEncoding = binary.BigEndian

	largeTimeout  = 100000 * time.Hour
	largeDeadline = time.Now().Add(100000 * time.Hour)
)

// netError implements the interface net.Error
type netError struct {
	err       string
	timeout   bool
	temporary bool
}

func (e *netError) Error() string   { return e.err }
func (e *netError) Timeout() bool   { return e.timeout }
func (e *netError) Temporary() bool { return e.temporary }

// Session is a wrapper around a net.Conn that supports multiplexing.
type Session interface {
	net.Conn

	// Wrapped() exposes access to the net.Conn that's wrapped by this Session.
	Wrapped() net.Conn
}

// Stream is a net.Conn that also exposes access to the underlying Session
type Stream interface {
	net.Conn

	// Session() exposes access to the Session on which this Stream is running.
	Session() Session

	// Wrapped() exposes the wrapped connection (same thing as Session(), but
	// implements netx.WrappedConn interface)
	Wrapped() net.Conn
}

// BufferPool is a pool of reusable buffers
type BufferPool interface {
	// getForFrame gets a complete buffer large enough to hold an entire lampshade
	// frame
	getForFrame() []byte

	// Get gets a truncated buffer sized to hold the data portion of a lampshade
	// frame
	Get() []byte

	// Put returns a buffer back to the pool, indicating that it is safe to
	// reuse.
	Put([]byte)
}

// NewBufferPool constructs a BufferPool with the given maximum size in bytes
func NewBufferPool(maxBytes int) BufferPool {
	return &bufferPool{bpool.NewBytePool(maxBytes/maxFrameSize, maxFrameSize)}
}

type bufferPool struct {
	pool *bpool.BytePool
}

func (p *bufferPool) getForFrame() []byte {
	return p.pool.Get()
}

func (p *bufferPool) Get() []byte {
	return p.pool.Get()[:MaxDataLen]
}

func (p *bufferPool) Put(b []byte) {
	p.pool.Put(b)
}

func setFrameTypeAndID(header []byte, frameType byte, id uint16) {
	header[0] = frameType
	binaryEncoding.PutUint16(header[1:], id)
}

func newHeader(frameType byte, id uint16) []byte {
	header := make([]byte, headerSize)
	setFrameTypeAndID(header, frameType, id)
	return header
}

func withFrameType(header []byte, frameType byte) []byte {
	out := make([]byte, headerSize)
	copy(out, header)
	out[0] = frameType
	return out
}

func frameTypeAndID(header []byte) (byte, uint16) {
	return header[0], binaryEncoding.Uint16(header[1:])
}

func setFrameType(header []byte, frameType byte) {
	header[0] = frameType
}

func frameType(header []byte) byte {
	return header[0]
}

func ackWithFrames(header []byte, frames int32) []byte {
	// note - header and frames field are reversed to match the usual format for
	// data frames
	ack := make([]byte, ackFrameSize)
	copy(ack[winSize:], header)
	ack[winSize] = frameTypeACK
	binaryEncoding.PutUint32(ack, uint32(frames))
	return ack
}
