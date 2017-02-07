package connmux

import (
	"io"
	"net"
)

type listener struct {
	wrapped net.Listener
	pool    BufferPool
	errCh   chan error
	connCh  chan net.Conn
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
// pool - BufferPool to use
func WrapListener(wrapped net.Listener, pool BufferPool) net.Listener {
	l := &listener{
		wrapped: wrapped,
		pool:    pool,
		connCh:  make(chan net.Conn),
		errCh:   make(chan error),
	}
	go l.process()
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
	go func() {
		l.errCh <- ErrListenerClosed
	}()
	// Closing wrapped has the side effect of making the process loop terminate
	// because it will fail to accept from wrapped.
	return l.wrapped.Close()
}

func (l *listener) process() {
	for {
		conn, err := l.wrapped.Accept()
		if err != nil {
			l.errCh <- err
			return
		}
		go l.onConn(conn)
	}
}

func (l *listener) onConn(conn net.Conn) {
	b := make([]byte, sessionStartTotalLen)
	// Try to read start sequence
	_, err := io.ReadFull(conn, b)
	if err != nil {
		l.errCh <- err
		return
	}
	if string(b[:sessionStartHeaderLen]) == sessionStart {
		// It's a multiplexed connection
		// TODO: check the version
		windowSize := int(b[sessionStartTotalLen-1])
		startSession(conn, windowSize, l.pool, l.connCh, nil)
		return
	}

	// It's a normal connection
	l.connCh <- &preReadConn{conn, b}
}

// preReadConn is a conn that takes care of the fact that we've already read a
// little from it
type preReadConn struct {
	net.Conn
	buf []byte
}

func (prc *preReadConn) Read(b []byte) (int, error) {
	buffered := len(prc.buf)
	if buffered == 0 {
		return prc.Conn.Read(b)
	}
	needed := len(b)
	n := copy(b, prc.buf)
	var err error
	prc.buf = prc.buf[n:]
	remain := needed - n
	if remain > 0 {
		var n2 int
		n2, err = prc.Conn.Read(b[n:])
		n += n2
	}
	return n, err
}

// Wrapped implements the interface netx.WrappedConn
func (prc *preReadConn) Wrapped() net.Conn {
	return prc.Conn
}
