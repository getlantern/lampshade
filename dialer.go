package lampshade

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"time"

	"github.com/getlantern/ema"
)

var defaultDialTimeout = 30 * time.Second

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
	//                     If <=0, defaults to max uint16.
	MaxStreamsPerConn uint16

	// IdleInterval - If we haven't dialed any new connections within this
	//                interval, open a new physical connection on the next dial.
	IdleInterval time.Duration

	// PingInterval - how frequently to ping to calculate RTT, set to 0 to disable
	PingInterval time.Duration

	// RedialSessionInterval - how frequently to redial a new session when
	// there's no live session, for faster recovery after network failures.
	// Defaults to 5 seconds.
	// See https://github.com/getlantern/lantern-internal/issues/2534
	RedialSessionInterval time.Duration

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
	if opts.MaxStreamsPerConn <= 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}

	if opts.RedialSessionInterval <= 0 {
		opts.RedialSessionInterval = 5 * time.Second
	}
	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   maxLiveConns: %v  maxStreamsPerConn: %v   pingInterval: %v   cipher: %v",
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
	d := &dialer{
		windowSize:            opts.WindowSize,
		maxPadding:            opts.MaxPadding,
		maxStreamsPerConn:     opts.MaxStreamsPerConn,
		idleInterval:          opts.IdleInterval,
		pingInterval:          opts.PingInterval,
		redialSessionInterval: opts.RedialSessionInterval,
		pool:                  opts.Pool,
		cipherCode:            opts.Cipher,
		serverPublicKey:       opts.ServerPublicKey,
		liveSessions:          make(chan sessionIntf, opts.LiveConns),
		emaRTT:                ema.NewDuration(0, 0.5),
		dial:                  opts.Dial,
		pendingSessions:       make(chan *pendingSession, opts.LiveConns),
		lifecyle:              lc,
		name:                  opts.Name,
	}
	d.lifecyle.OnStart()
	for i := 0; i < opts.LiveConns-1; i++ {
		d.pendingSessions <- newPendingSession(d.name)
	}

	// We create another background session with a shorter dial timeout to ensure liveness in the case of network
	// disruptions.
	d.pendingSessions <- &pendingSession{
		name:         "liveness to " + d.name,
		dialTimeout:  5 * time.Second,
		sleepOnError: 1 * time.Second,
	}
	go d.maintainTCPConnections()
	return d
}

type dialer struct {
	windowSize            int
	maxPadding            int
	maxStreamsPerConn     uint16
	idleInterval          time.Duration
	pingInterval          time.Duration
	redialSessionInterval time.Duration
	pool                  BufferPool
	cipherCode            Cipher
	serverPublicKey       *rsa.PublicKey
	liveSessions          chan sessionIntf
	pendingSessions       chan *pendingSession
	emaRTT                *ema.EMA
	dial                  DialFN
	lifecyle              ClientLifecycleListener
	name                  string
}

// maintainTCPConnections maintains background TCP connection(s) and associated lampshade session(s)
func (d *dialer) maintainTCPConnections() (net.Conn, error) {
	for {
		select {
		case rs := <-d.pendingSessions:
			start := time.Now()
			s, err := d.startSession(rs)
			if err != nil {
				log.Debugf("Error starting session '%v': %v", rs.name, err.Error())
				time.Sleep(rs.sleepOnError)
				d.pendingSessions <- rs
			} else {
				log.Debugf("Created session in %v to %#v", time.Since(start), rs)
				d.liveSessions <- s
			}
		}
	}
}

func (d *dialer) Dial() (net.Conn, error) {
	return d.DialContext(context.Background())
}

func (d *dialer) DialContext(ctx context.Context) (net.Conn, error) {
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}
	c := s.createStream(ctx)
	select {
	case d.liveSessions <- s:
	default:
		log.Debugf("Maximum live sessions reached to %v", d.name)
	}

	return c, nil
}

func (d *dialer) getSession(ctx context.Context) (sessionIntf, error) {
	start := time.Now()
	for {
		select {
		case s := <-d.liveSessions:
			if s.isClosed() {
				// Closed sessions will trigger the creation of new ones, so keep waiting for a new session.
				continue
			}

			if !s.allowNewStream(d.maxStreamsPerConn) {
				log.Debugf("Maximum streams reached for session to %v", d.name)
				// The default number of streams per session is 65535, so this is unlikely to be reached.
				select {
				case d.pendingSessions <- newPendingSession(d.name):
				default:
				}
				continue
			}

			return s, nil

		case <-ctx.Done():
			elapsed := time.Since(start).Seconds()
			err := fmt.Errorf("No session available after %f seconds to %v", elapsed, d.name)
			return nil, err
		}
	}
}

func (d *dialer) EMARTT() time.Duration {
	return d.emaRTT.GetDuration()
}

func (d *dialer) startSession(rs *pendingSession) (*session, error) {
	lc := d.lifecyle.OnTCPStart()
	conn, err := d.dial(rs.dialTimeout)
	if err != nil {
		lc.OnTCPConnectionError(err)
		return nil, err
	}
	lc.OnTCPEstablished(conn)

	cs, err := newCryptoSpec(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create crypto spec for %v: %v", d.cipherCode, err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, cs)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate client init message: %v", err)
	}

	s, err := startSession(conn, d.windowSize, d.maxPadding, false, d.pingInterval, cs, clientInitMsg, d.pool,
		d.emaRTT, nil, nil, d.pendingSessions, rs, lc)

	if err != nil {
		lc.OnSessionError(err, err)
	} else {
		lc.OnSessionInit()
	}
	return s, err
}
