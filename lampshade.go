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
//  - all numeric fields are unsigned integers in BigEndian format
//
// Client Init Message
//
//   - 256 bytes
//   - combined with first data message to vary size
//
//   To initialize a session, the client sends the following, encrypted using
//   RSA OAEP using the server's PK
//
//     +---------+-----+---------+--------+---------+---------+
//     | Version | Win | Max Pad | Secret | Send IV | Recv IV |
//     +---------+-----+---------+--------+---------+---------+
//     |    1    |  1  |    1    |   16   |   16    |   16    |
//     +---------+-----+---------+--------+---------+---------+
//
//       Version - the version of the protocol (currently 1)
//
//       Win - transmit window size
//
//       Max Pad - maximum random padding
//
//       Secret - 128 bits of secret for AES128
//
//       Send IV - 128 bits of initialization vector for CTR mode on AES128 for
//                 messages from client -> server
//
//       Recv IV - 128 bits of initialization vector for CTR mode on AES128 for
//                 messages from server -> client
//
// Framing:
//
//   - all frames are encrypted with AES128 in CTR mode, using the secret and
//     IV sent in the Init Session message
//
//   +--------------+-----------+----------+--------+
//   | Message Type | Stream ID | Data Len |  Data  |
//   +--------------+-----------+----------+--------+
//   |       1      |     3     |     2    | <=8192 |
//   +--------------+-----------+----------+--------+
//
//   Message Type - 1 byte, indicates the message type.
//
//  		0 = data
//      1 = padding
//      2 = ack
//	  	3 = rst (close connection)
//
//   Stream ID - unique identifier for stream. (last field for ack and rst)
//
//   Data Len - length of data (only used for message type "data" and "padding")
//
//   Data - data (only used for message type "data" and "padding")
//
// Padding:
//
//   - used only when there weren't enough pending writes to coalesce
//   - size varies randomly based on max pad parameter in init message
//   - looks just like a standard frame, with empty data
//   - the "empty" data actually looks random on the wire since we encrypt with
//     AES in CTR mode
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
	winSize        = 1
	maxPaddingSize = 1
	secretSize     = 16
	ivSize         = 16

	protocolVersion1 = 1

	// framing
	idSize          = 4
	lenSize         = 2
	frameHeaderSize = idSize + lenSize

	// MaxDataLen is the maximum length of data in a lampshade frame.
	MaxDataLen = 8192

	maxFrameSize = idSize + lenSize + MaxDataLen

	// frame types
	frameTypeData    = 0
	frameTypePadding = 1
	frameTypeACK     = 2
	frameTypeRST     = 3

	maxID = (2 << 31) - 1

	coalesceThreshold = 1500 // basically this is the practical TCP MTU for anything traversing Ethernet
)

var (
	log = golog.LoggerFor("lampshade")

	ErrTimeout          = &netError{"i/o timeout", true, true}
	ErrConnectionClosed = &netError{"connection closed", false, false}
	ErrBrokenPipe       = &netError{"broken pipe", false, false}
	ErrListenerClosed   = &netError{"listener closed", false, false}

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

// NewBufferPool constructs a BufferPool with the given maximumSize
func NewBufferPool(maxSize int) BufferPool {
	return &bufferPool{bpool.NewBytePool(maxSize, maxFrameSize)}
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

func frameType(b []byte) byte {
	return b[0]
}

func setFrameType(b []byte, frameType byte) {
	b[0] = frameType
}
