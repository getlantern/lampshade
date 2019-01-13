package lampshade

import (
	"crypto/rsa"
	"fmt"
	"net"
	"time"
)

// DialerOpts configures options for creating Dialers
type DialerOpts struct {
	// WindowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
	WindowSize int

	// MaxPadding - maximum random padding to use when necessary.
	MaxPadding int

	// MaxConns - limits the number of physical connections.
	//                     If <=0, defaults 1.
	MaxConns uint16

	// MaxStreamsPerConn - limits the number of streams per physical connection.
	//                     If <=0, defaults to max uint16.
	MaxStreamsPerConn uint16

	// IdleInterval - If we haven't dialed any new connections within this
	//                interval, open a new physical connection on the next dial.
	IdleInterval time.Duration

	// PingInterval - how frequently to ping to calculate RTT, set to 0 to disable
	PingInterval time.Duration

	// Pool - BufferPool to use (required)
	Pool BufferPool

	// Cipher - which cipher to use, 1 = AES128 in CTR mode, 2 = ChaCha20
	Cipher Cipher

	// ServerPublicKey - if provided, this dialer will use encryption.
	ServerPublicKey *rsa.PublicKey
}

// NewDialer wraps the given dial function with support for lampshade. The
// returned Streams look and act just like regular net.Conns. The Dialer
// will multiplex everything over a single net.Conn until it encounters a read
// or write error on that Conn. At that point, it will dial a new conn for
// future streams, until there's a problem with that Conn, and so on and so
// forth.
//
// If a new physical connection is needed but can't be established, the dialer
// returns the underlying dial error.
func NewDialer(opts *DialerOpts) Dialer {
	if opts.WindowSize <= 0 {
		opts.WindowSize = defaultWindowSize
	}
	if opts.MaxConns <= 0 || opts.MaxConns > maxID {
		opts.MaxConns = 1
	}
	if opts.MaxStreamsPerConn <= 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}
	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   maxConns: %v  maxStreamsPerConn: %v   pingInterval: %v   cipher: %v",
		opts.WindowSize,
		opts.MaxPadding,
		opts.MaxConns,
		opts.MaxStreamsPerConn,
		opts.PingInterval,
		opts.Cipher)
	liveSessions := make(chan sessionInf, opts.MaxConns)
	liveSessions <- nullSession{}
	return &dialer{
		windowSize:       opts.WindowSize,
		maxPadding:       opts.MaxPadding,
		maxStreamPerConn: opts.MaxStreamsPerConn,
		idleInterval:     opts.IdleInterval,
		pingInterval:     opts.PingInterval,
		pool:             opts.Pool,
		cipherCode:       opts.Cipher,
		serverPublicKey:  opts.ServerPublicKey,
		liveSessions:     liveSessions,
	}
}

type dialer struct {
	windowSize       int
	maxPadding       int
	maxStreamPerConn uint16
	idleInterval     time.Duration
	pingInterval     time.Duration
	pool             BufferPool
	cipherCode       Cipher
	serverPublicKey  *rsa.PublicKey
	liveSessions     chan sessionInf
}

func (d *dialer) Dial(dial DialFN) (net.Conn, error) {
	return d.DialStream(dial)
}

func (d *dialer) DialStream(dial DialFN) (Stream, error) {
	current := <-d.liveSessions
	if !current.AllowNewStream(d.maxStreamPerConn, d.idleInterval) {
		current.MarkDefunct()
		var err error
		current, err = d.startSession(dial)
		if err != nil {
			return nil, err
		}
	}
	c := current.CreateStream()
	d.liveSessions <- current
	return c, nil
}

func (d *dialer) EMARTT() time.Duration {
	var rtt time.Duration
	current := <-d.liveSessions
	if current != nil {
		rtt = current.EMARTT()
	}
	d.liveSessions <- current
	return rtt
}

func (d *dialer) BoundTo(dial DialFN) BoundDialer {
	return &boundDialer{d, dial}
}

func (d *dialer) startSession(dial DialFN) (*session, error) {
	conn, err := dial()
	if err != nil {
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

	return startSession(conn, d.windowSize, d.maxPadding, d.pingInterval, cs, clientInitMsg, d.pool, nil, nil)
}

type boundDialer struct {
	Dialer

	dial DialFN
}

func (bd *boundDialer) Dial() (net.Conn, error) {
	return bd.Dialer.Dial(bd.dial)
}

func (bd *boundDialer) DialStream() (Stream, error) {
	return bd.Dialer.DialStream(bd.dial)
}
