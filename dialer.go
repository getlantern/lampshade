package lampshade

import (
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"
)

// DialerOpts configures options for creating Dialers
type DialerOpts struct {
	// WindowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
	WindowSize int

	// MaxPadding - maximum random padding to use when necessary.
	MaxPadding int

	// MaxStreamsPerConn - limits the number of streams per physical connection.
	//                     If <=0, defaults to max uint16.
	MaxStreamsPerConn uint16

	// IdleInterval - If we haven't dialed any new connections within this
	//                interval, open a new physical connection on the next dial.
	IdleInterval time.Duration

	// PingInterval - how frequently to ping to calculate RTT, set to 0 to disable
	PingInterval time.Duration

	// Pool - BufferPool to use
	Pool BufferPool

	// Cipher - which cipher to use, 1 = AES128 in CTR mode, 2 = ChaCha20
	Cipher Cipher

	// ServerPublicKey - if provided, this dialer will use encryption.
	ServerPublicKey *rsa.PublicKey
}

// NewDialer wraps the given dial function with support for multiplexing. The
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
	if opts.MaxStreamsPerConn <= 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}
	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   maxStreamsPerConn: %v   pingInterval: %v   cipher: %v",
		opts.WindowSize,
		opts.MaxPadding,
		opts.MaxStreamsPerConn,
		opts.PingInterval,
		opts.Cipher)
	return &dialer{
		windowSize:       opts.WindowSize,
		maxPadding:       opts.MaxPadding,
		maxStreamPerConn: opts.MaxStreamsPerConn,
		idleInterval:     opts.IdleInterval,
		pingInterval:     opts.PingInterval,
		pool:             opts.Pool,
		cipherCode:       opts.Cipher,
		serverPublicKey:  opts.ServerPublicKey,
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
	current          *session
	lastDialed       time.Time
	id               uint16
	mx               sync.Mutex
}

func (d *dialer) Dial(dial DialFN) (net.Conn, error) {
	return d.DialStream(dial)
}

func (d *dialer) DialStream(dial DialFN) (Stream, error) {
	d.mx.Lock()
	current := d.current
	idsExhausted := false
	if d.id > d.maxStreamPerConn {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		idsExhausted = true
		d.id = 0
	}
	idled := false
	if d.idleInterval > 0 {
		now := time.Now()
		idled = now.Sub(d.lastDialed) > d.idleInterval
		if idled {
			log.Debugf("No new connections in %v, will start new session", d.idleInterval)
		}
		d.lastDialed = now
	}

	// TODO: support pooling of connections (i.e. keep multiple physical connections in flight)
	if current == nil || idsExhausted || idled {
		var err error
		current, err = d.startSession(dial)
		if err != nil {
			d.mx.Unlock()
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
