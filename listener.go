package lampshade

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/getlantern/ops"
	"github.com/opentracing/opentracing-go"

	otlog "github.com/opentracing/opentracing-go/log"
)

type listener struct {
	wrapped          net.Listener
	pool             BufferPool
	serverPrivateKey *rsa.PrivateKey
	ackOnFirst       bool
	onError          func(conn net.Conn, err error)
	errCh            chan error
	connCh           chan net.Conn
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
	if onError == nil {
		onError = func(net.Conn, error) {}
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

var traceIPs = map[string]bool{
	"65.214.166.18":  true,
	"115.159.105.71": true,
}

func (l *listener) doOnConn(conn net.Conn) error {
	var ctx context.Context
	var span opentracing.Span
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	if _, ok := traceIPs[ip]; ok {
		log.Debugf("Tracing IP %v", ip)
		span = opentracing.StartSpan(fmt.Sprintf("lampshade-%v->%v", conn.RemoteAddr().String(), conn.LocalAddr().String()))
		defer span.Finish()
		ctx = opentracing.ContextWithSpan(context.Background(), span)
	} else {
		log.Debugf("Not tracing IP %v", ip)
		ctx = context.Background()
		noop := opentracing.NoopTracer{}
		span = noop.StartSpan("noop")
	}

	start := time.Now()
	// Read client init msg
	initMsg := make([]byte, clientInitSize)
	// Try to read start sequence
	_, err := io.ReadFull(conn, initMsg)
	if err != nil {
		errText := fmt.Sprintf("Unable to read client init msg %v after %v from %v ", err, time.Since(start), conn.RemoteAddr())
		span.LogFields(otlog.String("init-error", errText))
		span.SetTag("error", "1")
		fullErr := errors.New(errText)
		l.onError(conn, fullErr)
		return fullErr
	}
	windowSize, maxPadding, cs, err := decodeClientInitMsg(l.serverPrivateKey, initMsg)
	if err != nil {
		errText := fmt.Sprintf("Unable to decode client init msg from %v: %v", conn.RemoteAddr(), err)
		span.LogFields(otlog.String("decode-error", errText))
		span.SetTag("error", "1")
		fullErr := errors.New(errText)
		l.onError(conn, fullErr)
		return fullErr
	}

	startSession(ctx, conn, windowSize, maxPadding, l.ackOnFirst, 0, cs.reversed(), nil, l.pool, nil, l.connCh, nil)
	return nil
}
