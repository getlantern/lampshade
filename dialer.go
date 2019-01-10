package lampshade

import (
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

const (
	sessionAcquisitionTimeout = 30 * time.Second
	retrySessionAfter         = 5 * time.Second
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
		current:          eventual.NewValue(),
	}
}

type sessionAndError struct {
	s   *session
	err error
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
	current          eventual.Value
	lastDialed       time.Time
	id               uint16
	mx               sync.Mutex
}

func (d *dialer) Dial(dial DialFN) (net.Conn, error) {
	return d.DialStream(dial)
}

func (d *dialer) DialStream(dial DialFN) (Stream, error) {
	d.mx.Lock()
	idsExhausted := false
	if d.id > d.maxStreamPerConn {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		idsExhausted = true
		d.id = 0
	} else {
		d.id++
	}

	current := d.current
	id := d.id

	uninitialized := d.lastDialed.IsZero()
	idled := false
	if !uninitialized && d.idleInterval > 0 {
		now := time.Now()
		idled = now.Sub(d.lastDialed) > d.idleInterval
		if idled {
			log.Debugf("No new connections in %v, will start new session", d.idleInterval)
		}
		d.lastDialed = now
	}

	if uninitialized || idsExhausted || idled {
		if !uninitialized {
			// Need to run this on a goroutine because we call back to sessionClosed()
			// via the session's beforeClose callback, which needs the mutex that's
			// already locked here.
			go func() {
				s, err := getSession(current, sessionAcquisitionTimeout)
				if err == nil {
					s.markDefunct()
				}
			}()
		}

		log.Debugf("Attempting to start new session")
		current = eventual.NewValue()
		d.current = current
		d.lastDialed = time.Now()

		go d.initSession(current, dial)
	}
	d.mx.Unlock()

	_sae, ok := current.GetOrInit(sessionAcquisitionTimeout, retrySessionAfter, func(v eventual.Value) {
		log.Debugf("Failed to obtain a session within %v, will try to create a new one", retrySessionAfter)
		d.initSession(v, dial)
	})
	if !ok {
		return nil, errors.New("timed out waiting for session")
	}

	sae := _sae.(*sessionAndError)
	if sae.err != nil {
		return nil, sae.err
	}

	c, _ := sae.s.getOrCreateStream(id)
	return c, nil
}

func (d *dialer) EMARTT() time.Duration {
	var rtt time.Duration
	d.mx.Lock()
	current := d.current
	d.mx.Unlock()

	s, err := getSession(current, 0)
	if err == nil {
		rtt = s.EMARTT()
	}
	return rtt
}

func (d *dialer) BoundTo(dial DialFN) BoundDialer {
	return &boundDialer{d, dial}
}

func (d *dialer) initSession(current eventual.Value, dial DialFN) {
	s, err := d.startSession(dial)
	if err != nil {
		// if we fail to start a session, we clear the current session eventual.Value
		// so that the next attempt to obtain a stream will start fresh.
		d.mx.Lock()
		d.clearSession()
		d.mx.Unlock()
		// the below notifies any DialStream calls that are still waiting for a
		// session about the error, which will cause them to fail immediately and
		// return the error to the caller.
		current.SetIfEmpty(&sessionAndError{nil, err})
		return
	}
	if !current.SetIfEmpty(&sessionAndError{s, nil}) {
		log.Debug("An earlier startSession succeeded, discarding this session")
		s.Close()
	}
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

	s, err := startSession(conn, d.windowSize, d.maxPadding, d.pingInterval, cs, clientInitMsg, d.pool, nil, d.sessionClosed)
	if err != nil {
		return nil, fmt.Errorf("Unable to start session: %v", err)
	}
	return s, nil
}

func (d *dialer) sessionClosed(s *session) {
	d.mx.Lock()
	current, _ := getSession(d.current, 0)
	if current == s {
		log.Debug("Current session no longer usable, clearing")
		d.clearSession()
	}
	d.mx.Unlock()
}

func (d *dialer) clearSession() {
	d.current = eventual.NewValue()
	d.lastDialed = time.Time{}
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

func getSession(current eventual.Value, timeout time.Duration) (*session, error) {
	_sae, ok := current.Get(timeout)
	if !ok {
		return nil, errors.New("timed out waiting for session")
	}
	sae := _sae.(*sessionAndError)
	return sae.s, sae.err
}
