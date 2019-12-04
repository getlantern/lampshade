package lampshade

import (
	"crypto/rsa"
	"io"
	"io/ioutil"
	"math"
	"net"
	"time"

	"github.com/getlantern/ops"
	lru "github.com/hashicorp/golang-lru"
)

const defaultInitMsgTimeout = 5 * time.Second

type listener struct {
	wrapped          net.Listener
	pool             BufferPool
	serverPrivateKey *rsa.PrivateKey
	ackOnFirst       bool
	onError          func(conn net.Conn, err error)
	errCh            chan error
	connCh           chan net.Conn

	// initMsgTimeout controls how long the listener will wait before responding to bad client init
	// messages. This applies in 3 situations:
	//   1. The client has sent some, but not all of the init message. This situation is salvagable
	//      if the client sends the remainder of the init message.
	//   2. The client sends an init message of the proper length, but we fail to decode it.
	//   3. The client sends an init message that is too long.
	// It is important that each situation be indistinguishable to a client. This is to avoid
	// leaking information to probes (from bad actors) that we have a fixed-size init message. Our
	// approach is to always close the connection after the init message timeout has elapsed.
	initMsgTimeout time.Duration

	keyCache         *lru.Cache
	maxClientInitAge time.Duration
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
// serverPrivateKey - if provided, this listener will expect connections to use
//                    encryption
//
// ackOnFirst - forces an immediate ACK after receiving the first frame, which could help defeat timing attacks
//
func WrapListener(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey, ackOnFirst bool) net.Listener {
	return WrapListenerIncludingErrorHandler(wrapped, pool, serverPrivateKey, ackOnFirst, nil)
}

// WrapListenerIncludingErrorHandler is like WrapListener and also supports a
// callback for errors on accepting new connections.
func WrapListenerIncludingErrorHandler(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey, ackOnFirst bool, onError func(net.Conn, error)) net.Listener {
	return WrapListenerRememberingKeys(wrapped, pool, serverPrivateKey, ackOnFirst, 0, onError)
}

// WrapListenerRememberingKeys is like WrapListenerIncludingErrorHandler and also uses an LRU cache to thwart replays of client init
// messages.
func WrapListenerRememberingKeys(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey, ackOnFirst bool, keyCacheSize int, onError func(net.Conn, error)) net.Listener {
	return WrapListenerLimitingInitAge(wrapped, pool, serverPrivateKey, ackOnFirst, keyCacheSize, 0, onError)
}

// WrapListenerLimitingInitAge is like WrapListenerRememberingKeys and also limits the maximum age of client init messages
func WrapListenerLimitingInitAge(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey, ackOnFirst bool, keyCacheSize int, maxClientInitAge time.Duration, onError func(net.Conn, error)) net.Listener {
	if onError == nil {
		onError = func(net.Conn, error) {}
	}

	if maxClientInitAge <= 0 {
		maxClientInitAge = time.Duration(math.MaxInt64)
	}

	// TODO: add a maxWindowSize
	l := &listener{
		wrapped:          wrapped,
		pool:             pool,
		serverPrivateKey: serverPrivateKey,
		ackOnFirst:       ackOnFirst,
		onError:          onError,
		connCh:           make(chan net.Conn),
		errCh:            make(chan error),
		initMsgTimeout:   defaultInitMsgTimeout,
		maxClientInitAge: maxClientInitAge,
	}
	if keyCacheSize > 0 {
		l.keyCache, _ = lru.New(keyCacheSize)
		if l.keyCache != nil {
			log.Debugf("Caching up to %d keys to prevent replays", keyCacheSize)
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
		readDeadline      = start.Add(l.initMsgTimeout)
		clearReadDeadline = func(c net.Conn) { c.SetReadDeadline(time.Time{}) }
		initMsg           = make([]byte, clientInitSize)
	)

	conn.SetReadDeadline(readDeadline)
	_, err := io.ReadFull(conn, initMsg)
	if err != nil {
		fullErr := log.Errorf("Unable to read client init msg %v after %v from %v ", err, time.Since(start), conn.RemoteAddr())
		time.Sleep(time.Until(readDeadline))
		clearReadDeadline(conn)
		l.onError(conn, fullErr)
		return fullErr
	}

	windowSize, maxPadding, cs, ts, err := decodeClientInitMsg(l.serverPrivateKey, initMsg)
	var fullErr error
	if err != nil {
		fullErr = log.Errorf("Unable to decode client init msg from %v: %v", conn.RemoteAddr(), err)
	} else if !ts.IsZero() && time.Now().Sub(ts) > l.maxClientInitAge {
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
		// Continue reading from the peer until the read deadline.
		io.Copy(ioutil.Discard, conn)
		clearReadDeadline(conn)
		l.onError(conn, fullErr)
		return fullErr
	}
	clearReadDeadline(conn)
	startSession(conn, windowSize, maxPadding, l.ackOnFirst, 0, cs.reversed(), nil, l.pool, nil, l.connCh, nil)
	return nil
}
