package lampshade

import (
	"context"
	"crypto/rsa"
	"errors"
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
func NewDialer(opts *DialerOpts) Dialer {
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
	liveSessions <- nullSession{}
	return &dialer{
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
	}
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
	emaRTT                *ema.EMA
}

func (d *dialer) Dial(lifecycle LifecycleListener, dial DialFN) (net.Conn, error) {
	return d.DialContext(context.Background(), lifecycle, dial)
}

func (d *dialer) DialContext(ctx context.Context, lifecycle LifecycleListener, dial DialFN) (net.Conn, error) {
	s, err := d.getOrCreateSession(ctx, lifecycle, dial)
	if err != nil {
		return nil, err
	}
	c := s.CreateStream(lifecycle)
	d.returnSession(s)
	return c, nil
}

func (d *dialer) getNumLivePending() int {
	d.muNumLivePending.Lock()
	numLivePending := d.numLive + d.numPending
	d.muNumLivePending.Unlock()
	return numLivePending
}

func (d *dialer) getOrCreateSession(ctx context.Context, lifecycle LifecycleListener, dial DialFN) (sessionIntf, error) {
	newSession := func(cap int) {
		d.muNumLivePending.Lock()
		if d.numLive+d.numPending >= cap {
			d.muNumLivePending.Unlock()
			return
		}
		d.numPending++
		d.muNumLivePending.Unlock()
		go func() {
			s, err := d.startSession(lifecycle, dial)
			d.muNumLivePending.Lock()
			d.numPending--
			if err != nil {
				d.muNumLivePending.Unlock()
				return
			}
			d.numLive++
			d.muNumLivePending.Unlock()
			log.Debug("Adding new real session...")
			d.liveSessions <- s
		}()
	}
	for {
		select {
		case s := <-d.liveSessions:
			if s.AllowNewStream(d.maxStreamsPerConn) {
				log.Debug("Stream allowed...")
				return s, nil
			}
			d.muNumLivePending.Lock()
			d.numLive--
			d.muNumLivePending.Unlock()
			s.MarkDefunct()
			log.Debugf("Calling newSession after not allowing new stream on session: %v", s.String())
			newSession(minLiveConns)
		case <-time.After(d.redialSessionInterval):
			log.Debugf("Calling newSession after redialSessionInterval")
			newSession(d.maxLiveConns)
		case <-ctx.Done():
			return nil, errors.New("No session available")
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

func (d *dialer) BoundTo(lifecycle LifecycleListener, dial DialFN) BoundDialer {
	return &boundDialer{d, dial}
}

func (d *dialer) startSession(lifecycle LifecycleListener, dial DialFN) (*session, error) {
	// Start with the span labeled as failed. When/if it succeeds, it will be renamed.
	ctx := context.Background()
	sessionContext := lifecycle.OnSessionInit(ctx)
	/*
		span := opentracing.StartSpan("lampshade-failed-TCP")
		defer span.Finish()

		sessionContext := opentracing.ContextWithSpan(ctx, span)
		dialSpan, ctx := opentracing.StartSpanFromContext(sessionContext, "lampshade-dial-init")
		defer dialSpan.Finish()
	*/
	lifecycle.OnTCPStart(sessionContext)
	start := time.Now()
	conn, err := dial()
	if err != nil {
		return nil, err
	}

	/*
		local := conn.LocalAddr().(*net.TCPAddr)
		span.SetTag("proto", "lampshade")
		span.SetTag("host", conn.RemoteAddr().String())
		span.SetTag("clientport", local.Port)
		span.SetOperationName(fmt.Sprintf("%s->%v", proxyName, local.Port))
	*/
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

	return startSession(sessionContext, conn, d.windowSize, d.maxPadding, false, d.pingInterval, cs, clientInitMsg, d.pool, d.emaRTT, nil, nil, lifecycle)
}

type boundDialer struct {
	Dialer

	dial DialFN
}

func (bd *boundDialer) Dial(lifecycle LifecycleListener) (net.Conn, error) {
	return bd.Dialer.Dial(lifecycle, bd.dial)
}

func (bd *boundDialer) DialContext(ctx context.Context, lifecycle LifecycleListener) (net.Conn, error) {
	return bd.Dialer.DialContext(ctx, lifecycle, bd.dial)
}
