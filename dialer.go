package lampshade

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"time"

	"github.com/getlantern/ema"
	"github.com/getlantern/ops"
)

// DialerOpts configures options for creating Dialers
type DialerOpts struct {
	// WindowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
	WindowSize int

	// MaxPadding - maximum random padding to use when necessary.
	MaxPadding int

	// LiveConns is the number of live connections to maintain to the server.
	// Defaults to 2.
	LiveConns int

	// MaxStreamsPerConn - limits the number of streams per physical connection.
	//                     If 0, defaults to max uint16.
	MaxStreamsPerConn uint16

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

	// The long dial timeout (in seconds) to use for one TCP connection to the lampshade server.
	LongDialTimeout int

	// The short dial timeout (in seconds) to use for the TCP connection to the lampshade server that is
	// charged with making lampshade more responsive to network disruptions or complete network outages.
	ShortDialTimeout int
}

type dialer struct {
	windowSize        int
	maxPadding        int
	maxStreamsPerConn uint16
	pingInterval      time.Duration
	pool              BufferPool
	cipherCode        Cipher
	serverPublicKey   *rsa.PublicKey
	liveSessions      chan sessionIntf
	pendingSessions   chan *sessionConfig
	sessionRequests   chan bool
	emaRTT            *ema.EMA
	dial              DialFN
	lifecyle          ClientLifecycleListener
	name              string
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
	if opts.LiveConns <= 0 {
		opts.LiveConns = 2
	}
	if opts.MaxStreamsPerConn == 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}
	if opts.LongDialTimeout <= 0 {
		opts.LongDialTimeout = 30
	}
	if opts.ShortDialTimeout <= 0 {
		opts.ShortDialTimeout = 5
	}
	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   liveConns: %v  maxStreamsPerConn: %v   pingInterval: %v   cipher: %v",
		opts.WindowSize,
		opts.MaxPadding,
		opts.LiveConns,
		opts.MaxStreamsPerConn,
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
	maxConns := opts.LiveConns * 2
	d := &dialer{
		windowSize:        opts.WindowSize,
		maxPadding:        opts.MaxPadding,
		maxStreamsPerConn: opts.MaxStreamsPerConn,
		pingInterval:      opts.PingInterval,
		pool:              opts.Pool,
		cipherCode:        opts.Cipher,
		serverPublicKey:   opts.ServerPublicKey,
		liveSessions:      make(chan sessionIntf, maxConns),
		emaRTT:            ema.NewDuration(0, 0.5),
		dial:              opts.Dial,
		pendingSessions:   make(chan *sessionConfig, maxConns),
		sessionRequests:   make(chan bool, 10),
		lifecyle:          lc,
		name:              opts.Name,
	}
	d.lifecyle.OnStart()
	for i := 0; i < opts.LiveConns-1; i++ {
		d.pendingSessions <- &sessionConfig{
			name:         "background to " + d.name,
			dialTimeout:  time.Duration(opts.LongDialTimeout) * time.Second,
			sleepOnError: 2 * time.Second,
		}
	}

	// We create another background session with a shorter dial timeout to ensure liveness in the case of network
	// disruptions.
	d.pendingSessions <- &sessionConfig{
		name:         "liveness to " + d.name,
		dialTimeout:  time.Duration(opts.ShortDialTimeout) * time.Second,
		sleepOnError: 1 * time.Second,
	}
	ops.Go(d.maintainTCPConnections)
	return d
}

// maintainTCPConnections maintains background TCP connection(s) and associated lampshade session(s)
func (d *dialer) maintainTCPConnections() {
	for sc := range d.pendingSessions {
		go d.trySession(sc)
	}
}

func (d *dialer) trySession(sc *sessionConfig) {
	start := time.Now()
	s, err := d.startSession(sc)
	if err != nil {
		log.Debugf("Error starting session '%v': %v", sc.name, err.Error())
		// Sleeping when there's an error is necessary particularly for the case where the network is down, as this
		// will then spin endlessly.
		time.Sleep(sc.sleepOnError)
		d.pendingSessions <- sc
	} else {
		log.Debugf("Created session in %v to %#v", time.Since(start), sc)
		d.recycleSession(s)
	}
}

func (d *dialer) recycleSession(s sessionIntf) {
	if !s.allowNewStream(d.maxStreamsPerConn) {
		log.Debugf("Maximum streams reached for session to %v", d.name)
		// The default number of streams per session is 65535, so this is unlikely to be reached. If it is, we create
		// an additional session with the same configuration as the full session.
		go func() {
			d.pendingSessions <- s.getSessionConfig()
		}()
		return
	}
	// We now have a new or established TCP connection/session. At this point two things can happen:
	// 1) The connection can be closed for any reason, in which case we want to request a new one
	// 2) A dialer can request the session. In that case, it will retrieve the session.
	select {
	case <-s.getCloseCh():
		log.Debugf("Session closed before requested. Requesting new session: %#v", s.getSessionConfig())
		d.pendingSessions <- s.getSessionConfig()
	case <-d.sessionRequests:
		d.liveSessions <- s
	}
}

func (d *dialer) Dial() (net.Conn, error) {
	return d.DialContext(context.Background())
}

func (d *dialer) DialContext(ctx context.Context) (net.Conn, error) {
	s, err := d.getSession(ctx)
	if err != nil {
		// If we continually can't get sessions, eventually sessionRequests will fill up. Make sure
		// we drain it on errors.
		<-d.sessionRequests
		return nil, err
	}
	go d.recycleSession(s)
	return s.createStream(ctx), nil
}

func (d *dialer) getSession(ctx context.Context) (sessionIntf, error) {
	d.sessionRequests <- true
	start := time.Now()
	for {
		select {
		case s := <-d.liveSessions:
			if s.isClosed() {
				// Closed sessions will trigger the creation of new ones, so keep waiting for a new session.
				log.Debugf("Found closed session. Continuing")
				continue
			}
			return s, nil

		case <-ctx.Done():
			err := fmt.Errorf("no session available after %v to %v", time.Since(start), d.name)
			return nil, err
		}
	}
}

func (d *dialer) EMARTT() time.Duration {
	return d.emaRTT.GetDuration()
}

func (d *dialer) startSession(rs *sessionConfig) (*session, error) {
	lc := d.lifecyle.OnTCPStart()
	cs, err := newCryptoSpec(d.cipherCode)
	if err != nil {
		lc.OnSessionError(err, err)
		return nil, fmt.Errorf("unable to create crypto spec for %v: %v", d.cipherCode, err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, cs)
	if err != nil {
		lc.OnSessionError(err, err)
		return nil, fmt.Errorf("unable to generate client init message: %v", err)
	}

	conn, err := d.dial(rs.dialTimeout)
	if err != nil {
		lc.OnTCPConnectionError(err)
		return nil, err
	}
	lc.OnTCPEstablished(conn)

	s, err := startSession(conn, d.windowSize, d.maxPadding, false, d.pingInterval, cs, clientInitMsg, d.pool,
		d.emaRTT, nil, nil, rs, lc)

	if err != nil {
		s.Close()
		lc.OnSessionError(err, err)
	} else {
		lc.OnSessionInit()
	}
	return s, err
}
