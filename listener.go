package lampshade

import (
	"crypto/rsa"
	"io"
	"io/ioutil"
	"math"
	"net"
	"time"

	"github.com/getlantern/idletiming"
	"github.com/getlantern/netx"
	"github.com/getlantern/ops"
	lru "github.com/hashicorp/golang-lru"
)

const forever = time.Duration(math.MaxInt64)

// ListenerOpts provides options for configuring a Listener
type ListenerOpts struct {
	// AckOnFirst forces an immediate ACK after receiving the first frame, which could help defeat timing attacks
	AckOnFirst bool

	// InitMsgTimeout controls how long the listener will wait before responding to bad client init
	// messages. This applies in 3 situations:
	//   1. The client has sent some, but not all of the init message. This situation is salvagable
	//      if the client sends the remainder of the init message.
	//   2. The client sends an init message of the proper length, but we fail to decode it.
	//   3. The client sends an init message that is too long.
	//
	// It is important that each situation be indistinguishable to a client. This is to avoid
	// leaking information to probes (from bad actors) that we have a fixed-size init message.
	// It is also important for this to be a really long time, as most servers in
	// the wild which fail to respond to an unknown protocol from the client will
	// keep the connection open indefinitely. Our approach is to always close the
	// connection after the init message timeout has elapsed.
	//
	// The default value is forever
	InitMsgTimeout time.Duration

	// KeyCacheSize enables and sizes a cache of previously seen client keys to
	// protect against replay attacks.
	KeyCacheSize int

	// MaxClientInit age limits the maximum allowed age of client init messages if
	// and only if the init message includes a timestamp field. This helps protect
	// against replay attacks.
	MaxClientInitAge time.Duration

	// Optional callback for errors that arise when accepting connectinos
	OnError func(net.Conn, error)
}

func (opts *ListenerOpts) withDefaults() *ListenerOpts {
	out := &ListenerOpts{}
	if opts != nil {
		*out = *opts
	}
	if out.InitMsgTimeout <= 0 {
		out.InitMsgTimeout = forever
	}

	if out.MaxClientInitAge <= 0 {
		out.MaxClientInitAge = forever
	}

	if out.OnError == nil {
		out.OnError = func(net.Conn, error) {}
	}

	return out
}

type listener struct {
	wrapped          net.Listener
	pool             BufferPool
	serverPrivateKey *rsa.PrivateKey
	opts             *ListenerOpts

	keyCache *lru.Cache
	errCh    chan error
	connCh   chan net.Conn
}

// WrapListener wraps the given listener with support for multiplexing. Only
// connections that start with the special session start sequence will be
// multiplexed, otherwise connections behave as normal. This means that a single
// listener can be used to serve clients that do multiplexing as well as other
// clients that don't.
//
// Multiplexed sessions can only be initiated immediately after opening a
// connection to the Listener.
//
// wrapped - the net.Listener to wrap
//
// pool - BufferPool to use
//
// serverPrivateKey - RSA key to decrypt client init messages
//
// opts - Options configuring the listener
//
func WrapListener(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey, opts *ListenerOpts) net.Listener {

	// TODO: add a maxWindowSize
	l := &listener{
		wrapped:          wrapped,
		pool:             pool,
		serverPrivateKey: serverPrivateKey,
		opts:             opts.withDefaults(),
		connCh:           make(chan net.Conn),
		errCh:            make(chan error),
	}
	if opts.KeyCacheSize > 0 {
		l.keyCache, _ = lru.New(opts.KeyCacheSize)
		if l.keyCache != nil {
			log.Debugf("Caching up to %d keys to prevent replays", opts.KeyCacheSize)
		}
	}
	ops.Go(l.process)
	trackStats()
	return l
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	}
}

func (l *listener) Addr() net.Addr {
	return l.wrapped.Addr()
}

func (l *listener) Close() error {
	ops.Go(func() {
		l.errCh <- ErrListenerClosed
	})
	// Closing wrapped has the side effect of making the process loop terminate
	// because it will fail to accept from wrapped.
	return l.wrapped.Close()
}

func (l *listener) process() {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, err := l.wrapped.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				// delay code based on net/http.Server
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Errorf("lampshade: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			l.errCh <- err
			return
		}
		tempDelay = 0
		ops.Go(func() { l.onConn(conn) })
	}
}

func (l *listener) onConn(conn net.Conn) {
	err := l.doOnConn(conn)
	if err != nil {
		conn.Close()
	}
}

func (l *listener) doOnConn(conn net.Conn) error {
	// We always wait for l.initMsgTimeout before responding to bad init messages. See
	// listener.initMsgTimeout for more detail.

	var (
		start             = time.Now()
		readDeadline      = start.Add(l.opts.InitMsgTimeout)
		clearReadDeadline = func(c net.Conn) { c.SetReadDeadline(time.Time{}) }
		initMsg           = make([]byte, clientInitSize)
	)

	// Handle pausing of idletiming to keep it from superseding our InitMsgTimeout
	unpauseIdleTiming := func() {
		// do nothing
	}
	netx.WalkWrapped(conn, func(wrapped net.Conn) bool {
		idleConn, ok := wrapped.(*idletiming.IdleTimingConn)
		if ok {
			unpauseIdleTiming = idleConn.Pause()
			return false
		}
		return true
	})

	consumeInboundTillDeadlineThenFail := func(fullErr error) error {
		start := time.Now()
		defer func() {
			log.Debugf("Finished consuming inbound till deadline in %v", time.Now().Sub(start))
		}()
		io.Copy(ioutil.Discard, conn)
		clearReadDeadline(conn)
		l.opts.OnError(conn, fullErr)
		unpauseIdleTiming()
		conn.Close()
		return fullErr
	}

	conn.SetReadDeadline(readDeadline)
	_, err := io.ReadFull(conn, initMsg)
	if err != nil {
		fullErr := log.Errorf("Unable to read client init msg %v after %v from %v ", err, time.Since(start), conn.RemoteAddr())
		return consumeInboundTillDeadlineThenFail(fullErr)
	}

	windowSize, maxPadding, cs, ts, err := decodeClientInitMsg(l.serverPrivateKey, initMsg)
	var fullErr error
	if err != nil {
		fullErr = log.Errorf("Unable to decode client init msg from %v: %v", conn.RemoteAddr(), err)
	} else if !ts.IsZero() && time.Now().Sub(ts) > l.opts.MaxClientInitAge {
		fullErr = log.Errorf("Detected excessively old client init message from %v", conn.RemoteAddr())
	} else if l.keyCache != nil {
		key := string(cs.secret)
		if l.keyCache.Contains(key) {
			fullErr = log.Errorf("Detected replay of known secret from %v", conn.RemoteAddr())
		} else {
			l.keyCache.Add(key, nil)
		}
	}

	if fullErr != nil {
		return consumeInboundTillDeadlineThenFail(fullErr)
	}

	clearReadDeadline(conn)
	unpauseIdleTiming()
	startSession(conn, windowSize, maxPadding, l.opts.AckOnFirst, 0, cs.reversed(), nil, l.pool, nil, l.connCh, nil)
	return nil
}
