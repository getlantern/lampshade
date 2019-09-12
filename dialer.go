package lampshade

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/getlantern/ema"
	"github.com/getlantern/ops"
)

const (
	defaultIdleInterval    = 30 * time.Second
	defaultSlowDialTimeout = 30 * time.Second
	defaultFastDialTimeout = 5 * time.Second
)

// DialerOpts configures options for creating Dialers
type DialerOpts struct {
	// WindowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
	WindowSize int

	// MaxPadding - maximum random padding to use when necessary.
	MaxPadding int

	// MaxStreamsPerConn - limits the number of streams per physical connection.
	//                     If 0, defaults to max uint16.
	MaxStreamsPerConn uint16

	// IdleInterval - If we haven't dialed any new connections within this
	//                interval, open a new physical connection on the next dial.
	IdleInterval time.Duration

	// SlowDialTimeout governs the timeout for the slow dialer
	SlowDialTimeout time.Duration

	// FastDialTimeout governs the timeout for the fast dialer
	FastDialTimeout time.Duration

	// PingInterval - how frequently to ping to calculate RTT, set to 0 to disable
	PingInterval time.Duration

	// Pool - BufferPool to use (required)
	Pool BufferPool

	// Cipher - which cipher to use, 1 = AES128 in CTR mode, 2 = ChaCha20
	Cipher Cipher

	// ServerPublicKey - if provided, this dialer will use encryption.
	ServerPublicKey *rsa.PublicKey

	// Dial is the dial function to use for creating new TCP connections.
	Dial DialFN

	// Lifecycle is a listener for lifecycle events in lampshade.
	Lifecycle ClientLifecycleListener

	// Name is a more descriptive name of the dialer.
	Name string
}

type dialer struct {
	windowSize        int
	maxPadding        int
	maxStreamsPerConn uint16
	idleInterval      time.Duration
	pingInterval      time.Duration
	pool              BufferPool
	cipherCode        Cipher
	serverPublicKey   *rsa.PublicKey
	currentSessionMX  sync.Mutex
	currentSession    chan *session
	pendingSessions   chan *session
	sessionRequested  chan bool
	emaRTT            *ema.EMA
	dial              DialFN
	lifecyle          ClientLifecycleListener
	name              string
	closed            chan interface{}
	closeOnce         sync.Once
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
	if opts.IdleInterval <= 0 {
		opts.IdleInterval = defaultIdleInterval
	}
	if opts.MaxStreamsPerConn == 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}
	if opts.SlowDialTimeout == 0 {
		opts.SlowDialTimeout = defaultSlowDialTimeout
	}
	if opts.FastDialTimeout == 0 {
		opts.FastDialTimeout = defaultFastDialTimeout
	}

	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   maxStreamsPerConn: %v   slowDialTimeout: %v   fastDialTimeout: %v   idleInterval: %v    pingInterval: %v   cipher: %v",
		opts.WindowSize,
		opts.MaxPadding,
		opts.MaxStreamsPerConn,
		opts.SlowDialTimeout,
		opts.FastDialTimeout,
		opts.IdleInterval,
		opts.PingInterval,
		opts.Cipher)
	var lc ClientLifecycleListener
	if opts.Lifecycle != nil {
		lc = opts.Lifecycle
	} else {
		lc = NoopClientLifecycleListener()
	}

	// We allow more than LiveConns here to accommodate the rare case that individual sessions
	// fill up with streams, and we need more.
	d := &dialer{
		windowSize:        opts.WindowSize,
		maxPadding:        opts.MaxPadding,
		maxStreamsPerConn: opts.MaxStreamsPerConn,
		idleInterval:      opts.IdleInterval,
		pingInterval:      opts.PingInterval,
		pool:              opts.Pool,
		cipherCode:        opts.Cipher,
		serverPublicKey:   opts.ServerPublicKey,
		currentSession:    make(chan *session, 1),
		pendingSessions:   make(chan *session),
		sessionRequested:  make(chan bool, 1),
		emaRTT:            ema.NewDuration(0, 0.5),
		dial:              opts.Dial,
		lifecyle:          lc,
		name:              opts.Name,
		closed:            make(chan interface{}),
	}

	d.lifecyle.OnStart()
	d.requestSession() // request an initial value for current session
	ops.Go(func() {
		op := ops.Begin("maintain_current_session").
			Set("dialer_name", opts.Name).
			Set("idle_interval", opts.IdleInterval)
		defer op.End()
		d.maintainCurrentSession()
	})
	ops.Go(func() {
		// Start some sessions using a slow dial timeout to remain tolerant of poor network latency
		op := ops.Begin("start_sessions_slow_dial").
			Set("dialer_name", opts.Name).
			Set("idle_interval", opts.IdleInterval)
		defer op.End()
		d.startSessions(opts.SlowDialTimeout)
	})
	ops.Go(func() {
		// Start some sessions using a fast dial timeout to make sure that we recover quickly from temporary network outages
		op := ops.Begin("start_sessions_fast_dial").
			Set("dialer_name", opts.Name).
			Set("idle_interval", opts.IdleInterval)
		defer op.End()
		d.startSessions(opts.FastDialTimeout)
	})
	return d
}

func (d *dialer) Dial() (net.Conn, error) {
	return d.DialContext(context.Background())
}

func (d *dialer) DialContext(ctx context.Context) (net.Conn, error) {
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.createStream(ctx), nil
}

func (d *dialer) EMARTT() time.Duration {
	return d.emaRTT.GetDuration()
}

func (d *dialer) getSession(ctx context.Context) (*session, error) {
	start := time.Now()
	for {
		select {
		case s := <-d.currentSession:
			if !s.allowNewStream(d.maxStreamsPerConn) {
				log.Debug("Session doesn't allow new streams, try again")
				d.requestSession()
				continue
			}
			d.setCurrentSession(s)
			log.Debugf("Returning session in %v", time.Since(start))
			return s, nil

		case <-ctx.Done():
			err := fmt.Errorf("No session available after %v to %v", time.Since(start), d.name)
			return nil, err
		}
	}
}

func (d *dialer) requestSession() {
	select {
	case d.sessionRequested <- true:
		// okay
	default:
		// already have a pending request
	}
}

func (d *dialer) maintainCurrentSession() {
	defer func() {
		d.currentSessionMX.Lock()
		close(d.currentSession)
		d.currentSessionMX.Unlock()
	}()

	for {
		select {
		case <-d.sessionRequested:
			select {
			case s := <-d.pendingSessions:
				// Always set the current session to the first available of the pending sessions
				d.setCurrentSession(s)
			case <-d.closed:
				return
			}
		case <-d.closed:
			return
		}
	}
}

func (d *dialer) startSessions(dialTimeout time.Duration) {
	for {
		log.Debug("Starting session")
		s, err := d.startSession(dialTimeout)
		if err != nil {
			log.Errorf("Unable to start session: %v", err)
			time.Sleep(dialTimeout / 5)
			select {
			case <-d.closed:
				return
			default:
				continue
			}
		}
		log.Debug("Started session")
		select {
		case d.pendingSessions <- s:
			log.Debug("Session accepted")
		case <-time.After(d.idleInterval):
			log.Debug("Session idled before use, discarding")
			s.Close()
		case <-d.closed:
			return
		}
	}
}

func (d *dialer) startSession(dialTimeout time.Duration) (*session, error) {
	lc := d.lifecyle.OnTCPStart()
	cs, err := newCryptoSpec(d.cipherCode)
	if err != nil {
		lc.OnSessionError(err, err)
		return nil, fmt.Errorf("Unable to create crypto spec for %v: %v", d.cipherCode, err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, cs)
	if err != nil {
		lc.OnSessionError(err, err)
		return nil, fmt.Errorf("Unable to generate client init message: %v", err)
	}

	conn, err := d.dial(dialTimeout)
	if err != nil {
		lc.OnTCPConnectionError(err)
		return nil, err
	}
	lc.OnTCPEstablished(conn)

	s, err := startSession(conn, d.windowSize, d.maxPadding, false, d.pingInterval, cs, clientInitMsg, d.pool,
		d.emaRTT, nil, func(s *session) {
			cs := <-d.currentSession
			if cs == s {
				log.Debug("Discarding current session on close")
				d.requestSession()
			} else {
				d.setCurrentSession(cs)
			}
		}, lc)

	if err != nil {
		conn.Close()
		lc.OnSessionError(err, err)
	} else {
		lc.OnSessionInit()
	}
	return s, err
}

func (d *dialer) setCurrentSession(s *session) {
	d.currentSessionMX.Lock()
	select {
	case <-d.closed:
		log.Debug("Dialer closed, discarding session")
	default:
		d.currentSession <- s
		// okay
	}
	d.currentSessionMX.Unlock()
}

func (d *dialer) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}
