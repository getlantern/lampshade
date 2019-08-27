package lampshade

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/getlantern/ema"
)

const (
	minLiveConns = 1
)

// DialerOpts configures options for creating Dialers
type DialerOpts struct {
	// WindowSize - transmit window size in # of frames. If <= 0, defaults to 1250.
	WindowSize int

	// MaxPadding - maximum random padding to use when necessary.
	MaxPadding int

	// MaxLiveConns - limits the number of live physical connections on which
	// new streams can be created. If <=0, defaults to 1.
	MaxLiveConns int

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
func NewDialer(opts *DialerOpts, lifecycle ClientLifecycleListener, dial DialFN) Dialer {
	if opts.WindowSize <= 0 {
		opts.WindowSize = defaultWindowSize
	}
	if opts.MaxLiveConns <= 0 {
		opts.MaxLiveConns = 1
	}
	if opts.MaxStreamsPerConn == 0 || opts.MaxStreamsPerConn > maxID {
		opts.MaxStreamsPerConn = maxID
	}

	if opts.RedialSessionInterval <= 0 {
		opts.RedialSessionInterval = 5 * time.Second
	}
	log.Debugf("Initializing Dialer with   windowSize: %v   maxPadding: %v   maxLiveConns: %v  maxStreamsPerConn: %v   pingInterval: %v   cipher: %v",
		opts.WindowSize,
		opts.MaxPadding,
		opts.MaxLiveConns,
		opts.MaxStreamsPerConn,
		opts.PingInterval,
		opts.Cipher)
	liveSessions := make(chan sessionIntf, opts.MaxLiveConns)
	d := &dialer{
		windowSize:            opts.WindowSize,
		maxPadding:            opts.MaxPadding,
		maxStreamsPerConn:     opts.MaxStreamsPerConn,
		maxLiveConns:          opts.MaxLiveConns,
		idleInterval:          opts.IdleInterval,
		pingInterval:          opts.PingInterval,
		redialSessionInterval: opts.RedialSessionInterval,
		pool:                  opts.Pool,
		cipherCode:            opts.Cipher,
		serverPublicKey:       opts.ServerPublicKey,
		liveSessions:          liveSessions,
		numLive:               1, // the nullSession
		emaRTT:                ema.NewDuration(0, 0.5),
		lifecycle:             lifecycle,
		dial:                  dial,
		requiredSessions:      make(chan bool, 1),
	}
	d.requiredSessions <- true
	go d.maintainTCPConnection()
	return d
}

type dialer struct {
	windowSize            int
	maxPadding            int
	maxLiveConns          int
	maxStreamsPerConn     uint16
	idleInterval          time.Duration
	pingInterval          time.Duration
	redialSessionInterval time.Duration
	pool                  BufferPool
	cipherCode            Cipher
	serverPublicKey       *rsa.PublicKey
	muNumLivePending      sync.Mutex
	numLive               int
	numPending            int
	liveSessions          chan sessionIntf
	requiredSessions      chan bool
	emaRTT                *ema.EMA
	lifecycle             ClientLifecycleListener
	dial                  DialFN
}

func (d *dialer) maintainTCPConnection() (net.Conn, error) {
	for {
		select {
		case <-d.requiredSessions:
			start := time.Now()
			s, err := d.startSession(d.lifecycle, d.dial)
			if err != nil {
				d.lifecycle.OnTCPConnectionError(err)
				time.Sleep(2 * time.Second)
				d.requiredSessions <- true
			} else {
				log.Debugf("Created session in %v", time.Since(start))
				d.liveSessions <- s
			}
		}
	}
}

func (d *dialer) Dial() (net.Conn, error) {
	return d.DialContext(context.Background())
}

func (d *dialer) DialContext(ctx context.Context) (net.Conn, error) {
	ctx, s, err := d.getSession(ctx, d.lifecycle)
	if err != nil {
		return nil, err
	}
	c := s.CreateStream(ctx, d.lifecycle)

	//d.returnSession(s)
	return c, nil
}

func (d *dialer) getNumLivePending() int {
	d.muNumLivePending.Lock()
	numLivePending := d.numLive + d.numPending
	d.muNumLivePending.Unlock()
	return numLivePending
}

func (d *dialer) getSession(ctx context.Context, lifecycle ClientLifecycleListener) (context.Context, sessionIntf, error) {
	start := time.Now()
	for {
		select {
		case s := <-d.liveSessions:
			log.Debug("Got live session")
			d.liveSessions <- s
			log.Debug("Returned live session")
			if s.AllowNewStream(d.maxStreamsPerConn) {
				log.Debug("Stream allowed...")
				sessionCtx := lifecycle.OnSessionInit(ctx)
				return sessionCtx, s, nil
			}

			// If this session has maximized its streams (seems to rarely happen in practice), then trigger creating
			// a new session.
			d.requiredSessions <- true
			/*
				d.muNumLivePending.Lock()
				d.numLive--
				d.muNumLivePending.Unlock()
				s.MarkDefunct()
				log.Debugf("Calling newSession after not allowing new stream on session: %v", s.String())
				newSession(minLiveConns)
			*/
			/*
				case <-time.After(d.redialSessionInterval):
					log.Debugf("Calling newSession after redialSessionInterval")
					lifecycle.OnRedialSessionInterval(ctx)
					d.requiredSessions <- true
					//newSession(d.maxLiveConns)
			*/
		case <-ctx.Done():
			elapsed := time.Since(start).Seconds()
			err := fmt.Errorf("No session available after %f", elapsed)
			if elapsed < 2.0 {
				lifecycle.OnSessionError(err, nil)
			}
			return ctx, nil, err
		}
	}
}

func (d *dialer) returnSession(s sessionIntf) {
	addBack := true
	d.muNumLivePending.Lock()
	if d.numLive > minLiveConns {
		d.numLive--
		addBack = false
	}
	d.muNumLivePending.Unlock()
	if addBack {
		d.liveSessions <- s
	} else {
		s.MarkDefunct()
	}
}

func (d *dialer) EMARTT() time.Duration {
	return d.emaRTT.GetDuration()
}

func (d *dialer) startSession(lifecycle ClientLifecycleListener, dial DialFN) (*session, error) {
	//ctx = lifecycle.OnSessionInit(ctx)
	//lifecycle.OnTCPStart(ctx)
	start := time.Now()
	conn, err := dial()
	if err != nil {
		//lifecycle.OnTCPConnectionError(err)
		return nil, err
	}
	//lifecycle.OnTCPEstablished(conn)
	log.Debugf("Successfully created new lampshade TCP connection in %v seconds", time.Since(start).Seconds())
	cs, err := newCryptoSpec(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create crypto spec for %v: %v", d.cipherCode, err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, cs)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate client init message: %v", err)
	}

	return startSession(conn, d.windowSize, d.maxPadding, false, d.pingInterval, cs, clientInitMsg,
		d.pool, d.emaRTT, nil, nil, lifecycle)
}

func (d *dialer) dialerLifecycle(base ClientLifecycleListener) ClientLifecycleListener {
	return &dialerLifecycleWrapper{base, d}
}

type dialerLifecycleWrapper struct {
	ClientLifecycleListener
	d *dialer
}

func (dlw *dialerLifecycleWrapper) OnTCPClosed() {
	dlw.ClientLifecycleListener.OnTCPClosed()
	dlw.d.requiredSessions <- true
}
