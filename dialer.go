package lampshade

import (
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"
)

// NewDialer wraps the given dial function with support for multiplexing. The
// returned Streams look and act just like regular net.Conns. The Dialer
// will multiplex everything over a single net.Conn until it encounters a read
// or write error on that Conn. At that point, it will dial a new conn for
// future streams, until there's a problem with that Conn, and so on and so
// forth.
//
// If a new physical connection is needed but can't be established, the dialer
// returns the underlying dial error.
//
// windowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
//
// maxPadding - maximum random padding to use when necessary.
//
// maxStreamsPerConn - limits the number of streams per physical connection. If
//                     <=0, defaults to max uint16.
//
// pingInterval - how frequently to ping to calculate RTT, set to 0 to disable.
//
// pool - BufferPool to use
//
// cipherCode - which cipher to use, 1 = AES128 in CTR mode, 2 = ChaCha20
//
// serverPublicKey - if provided, this dialer will use encryption.
//
// dial - function to open an underlying connection.
func NewDialer(windowSize int, maxPadding int, maxStreamsPerConn uint16, pingInterval time.Duration, pool BufferPool, cipherCode Cipher, serverPublicKey *rsa.PublicKey, dial func() (net.Conn, error)) Dialer {
	if windowSize <= 0 {
		windowSize = defaultWindowSize
	}
	if maxStreamsPerConn <= 0 || maxStreamsPerConn > maxID {
		maxStreamsPerConn = maxID
	}
	return &dialer{
		doDial:           dial,
		windowSize:       windowSize,
		maxPadding:       maxPadding,
		maxStreamPerConn: maxStreamsPerConn,
		pingInterval:     pingInterval,
		pool:             pool,
		cipherCode:       cipherCode,
		serverPublicKey:  serverPublicKey,
	}
}

type dialer struct {
	doDial           func() (net.Conn, error)
	windowSize       int
	maxPadding       int
	maxStreamPerConn uint16
	pingInterval     time.Duration
	pool             BufferPool
	cipherCode       Cipher
	serverPublicKey  *rsa.PublicKey
	current          *session
	id               uint16
	mx               sync.Mutex
}

func (d *dialer) Dial() (net.Conn, error) {
	return d.DialStream()
}

func (d *dialer) DialStream() (Stream, error) {
	d.mx.Lock()
	current := d.current
	idsExhausted := false
	if d.id > d.maxStreamPerConn {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		idsExhausted = true
		d.id = 0
	}

	// TODO: support pooling of connections (i.e. keep multiple physical connections in flight)
	if current == nil || idsExhausted {
		var err error
		current, err = d.startSession()
		if err != nil {
			return nil, err
		}
	}
	id := d.id
	d.id++
	d.mx.Unlock()

	c, _ := current.getOrCreateStream(id)
	return c, nil
}

func (d *dialer) EMARTT() time.Duration {
	var rtt time.Duration
	d.mx.Lock()
	current := d.current
	d.mx.Unlock()
	if current != nil {
		rtt = current.EMARTT()
	}
	return rtt
}

func (d *dialer) startSession() (*session, error) {
	conn, err := d.doDial()
	if err != nil {
		d.mx.Unlock()
		return nil, err
	}

	cs, err := newCryptoSpec(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create crypto spec for %v: %v", d.cipherCode, err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, cs)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate client init message: %v", err)
	}

	d.current, err = startSession(conn, d.windowSize, d.maxPadding, d.pingInterval, cs, clientInitMsg, d.pool, nil, d.sessionClosed)
	if err != nil {
		return nil, fmt.Errorf("Unable to start session: %v", err)
	}
	return d.current, nil
}

func (d *dialer) sessionClosed(s *session) {
	d.mx.Lock()
	if d.current == s {
		log.Debug("Current session no longer usable, clearing")
		d.current = nil
	}
	d.mx.Unlock()
}
