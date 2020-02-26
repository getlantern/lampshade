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
//   Session initiation
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
//     +-----+---------+--------+--------+----------+----------+----------+----------+----+
//     | Win | Max Pad | Cipher | Secret | Send IV1 | Send IV2 | Recv IV1 | Recv IV2 | TS |
//     +-----+---------+--------+--------+----------+----------+----------+----------+----+
//     |  4  |    1    |    1   |   32   |    12    |    12    |    12    |    12    |  8 |
//     +-----+---------+--------+--------+----------+----------+----------+----------+----+
//
//       Win        - transmit window size in # of frames
//
//       Max Pad    - maximum random padding
//
//       Cipher     - specifies the AEAD cipher used for encrypting frames
//
//                      1 = None
//                      2 = AES128_GCM
//                      3 = ChaCha20_poly1305
//
//       Secret     - 256 bits of secret (used for Len and Frames encryption)
//
//       Send IV1/2 - 96 bits of initialization vector. IV1 is used for
//                    encrypting the frame length and IV2 is used for encrypting
//                    the data.
//
//       Recv IV1/2 - 96 bits of initialization vector. IV1 is used for
//                    decrypting the frame length and IV2 is used for decrypting
//                    the data.
//
//       TS         - Optional, this is the timestamp of the client init message
//                    in seconds since epoch.
//
// Session Framing:
//
//   Where possible, lampshade coalesces multiple stream-level frames into a
//   single session-level frame on the wire. The session-level frames follow
//   the below format. Len is encrypted using ChaCha20. Frames is encrypted
//   using the configured AEAD and the resulting MAC is stored in MAC.
//
//     +-----+---------+------+
//     | Len |  Frames |  MAC |
//     +-----+---------+------+
//     |  2  | <=65518 |  16  |
//     +-----+---------+------+
//
//     Len    - the length of the frame, not including the Len field itself.
//              This is encrypted using ChaCha20 to obscure the actual value.
//
//     Frames - the data of the app frames. Padding appears at the end of this.
//
//     MAC    - the MAC resulting from applying the AEAD to Frames.
//
// Encryption:
//
//   The Len field is encrypted using ChaCha20 as a stream cipher initialized
//   with a session-level initialization vector for obfuscation purposes. The
//   Frames field is encrypted using AEAD (either AES128_GCM or
//   ChaCha20_Poly1305) in order to prevent chosen ciphertext attacks. The nonce
//   for each message is derived from a session-level initialization vector
//   XOR'ed with a frame sequence number, similar AES128_GCM in TLS 1.3
//   (see https://blog.cloudflare.com/tls-nonce-nse/).
//
// Padding:
//
//   - used only when there weren't enough pending writes to coalesce
//   - size varies randomly based on max pad parameter in init message
//   - consists of empty data
//   - the "empty" data actually looks random on the wire since it's being
//     encrypted with a cipher in streaming or GCM mode.
//
// Stream Framing:
//
//   Stream frames follow the below format:
//
//     +------------+-----------+----------+--------+
//     |            |           | Data Len |        |
//     |            |           | / Frames |  Data  |
//     | Frame Type | Stream ID |   / TS   |        |
//     +------------+-----------+----------+--------+
//     |      1     |     2     |   2/4/8  | <=1443 |
//     +------------+-----------+----------+--------+
//
//     Frame Type - indicates the message type.
//
//                      0 = padding
//                      1 = data
//                    252 = ping
//                    253 = echo
//                    254 = ack
//                    255 = rst (close connection)
//
//     Stream ID  - unique identifier for stream. (last field for ack and rst)
//
//     Data Len   - length of data (for type "data" or "padding")
//
//     Frames     - number of frames being ACK'd (for type ACK)
//
//     Data       - data (for type "data" or "padding")
//
//     TS         - time at which ping packet was sent as 64-bit uint. This is
//                  a passthrough value, so the client implementation can put
//                  whatever it wants in here in order to calculate its RTT.
//                  (for type "ping" and "echo")
//
// Flow Control:
//
//   Stream-level flow control is managed using windows similarly to HTTP/2.
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
// Ping Protocol:
//
//   Dialers can optionally be configured to use an embedded ping/echo protocol
//   to maintain an exponential moving average round trip time (RTT). The ping
//   protocol is similar to an ICMP ping. The client sends a ping packet
//   containing a 64-bit unsigned integer timestamp and the server responds with
//   an echo containing that same timestamp. For blocking resistance and
//   efficiency, pings are only sent with other outgoing frames. If there's no
//   outgoing traffic, no pings will be sent.
//
package lampshade

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/mtime"
	"github.com/oxtoacart/bpool"
)

const (
	// client init message
	clientInitSize = 256
	winSize        = 4
	tsSize         = 8
	maxSecretSize  = 32
	metaIVSize     = 12

	// NoEncryption is no encryption
	NoEncryption = 1
	// AES128GCM is 128-bit AES in GCM mode
	AES128GCM = 2
	// ChaCha20Poly1305 is 256-bit ChaCha20Poly1305 with a 96-bit Nonce
	ChaCha20Poly1305 = 3

	// framing
	headerSize     = 3
	lenSize        = 2
	dataHeaderSize = headerSize + lenSize

	coalesceThreshold = 1448 // basically this is the practical TCP MSS for anything traversing Ethernet and using TCP timestamps
	maxFrameSize      = coalesceThreshold
	ackFrameSize      = headerSize + winSize
	pingFrameSize     = headerSize + tsSize

	// MaxDataLen is the maximum length of data in a lampshade frame.
	MaxDataLen = maxFrameSize - dataHeaderSize

	maxSessionFrameSize = (2 << 15) - 1

	// frame types
	frameTypePadding = 0
	frameTypeData    = 1
	frameTypePing    = 252
	frameTypeEcho    = 253
	frameTypeACK     = 254
	frameTypeRST     = 255

	ackRatio          = 10 // ack every 1/10 of window
	defaultWindowSize = 2 * 1024 * 1024 / MaxDataLen
	maxID             = (2 << 15) - 1
)

var (
	log = golog.LoggerFor("lampshade")

	// ErrTimeout indicates that an i/o operation timed out.
	ErrTimeout = &netError{"i/o timeout", true, true}
	// ErrConnectionClosed indicates that an i/o operation was attempted on a
	// closed stream.
	ErrConnectionClosed = &netError{"connection closed", false, false}
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

// StatsTracking is an interface for anything that tracks stats.
type StatsTracking interface {
	// EMARTT() gets the estimated moving average RTT for all streams created by
	// this Dialer.
	EMARTT() time.Duration
}

// DialFN is a function that dials the server
type DialFN func() (net.Conn, error)

// Dialer provides an interface for opening new lampshade connections.
type Dialer interface {
	StatsTracking

	// Dial creates a virtual connection to the lampshade server, using the given
	// DialFN to open a physical connection when necessary.
	Dial(dial DialFN) (net.Conn, error)

	// DialContext is the same as Dial but with the specific context.
	DialContext(ctx context.Context, dial DialFN) (net.Conn, error)

	// BoundTo returns a BoundDialer that uses the given DialFN to connect to the
	// lampshade server.
	BoundTo(dial DialFN) BoundDialer
}

// BoundDialer is a Dialer bound to a specific DialFN for connecting to the
// lampshade server.
type BoundDialer interface {
	StatsTracking

	// Dial creates a virtual connection to the lampshade server.
	Dial() (net.Conn, error)

	// DialContext is the same as Dial but with the specific context.
	DialContext(ctx context.Context) (net.Conn, error)
}

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

func ping() []byte {
	// note - header and ts field are reversed to match the usual format for
	// data frames
	ping := make([]byte, pingFrameSize)
	ping[tsSize] = frameTypePing
	binaryEncoding.PutUint64(ping, uint64(mtime.Now()))
	return ping
}

func echo() []byte {
	echo := make([]byte, pingFrameSize)
	echo[tsSize] = frameTypeEcho
	return echo
}
