package connmux

import (
	"net"
	"sync"
)

// Dialer is like StreamDialer but provides a function that returns a net.Conn
// for easier integration with code that needs this interface.
func Dialer(windowSize int, maxStreamsPerConn uint32, pool BufferPool, dial func() (net.Conn, error)) func() (net.Conn, error) {
	d := StreamDialer(windowSize, maxStreamsPerConn, pool, dial)
	return func() (net.Conn, error) {
		return d()
	}
}

// StreamDialer wraps the given dial function with support for multiplexing. The
// returned Streams look and act just like regular net.Conns. The Dialer
// will multiplex everything over a single net.Conn until it encounters a read
// or write error on that Conn. At that point, it will dial a new conn for
// future streams, until there's a problem with that Conn, and so on and so
// forth.
//
// If a new physical connection is needed but can't be established, the dialer
// returns the underlying dial error.
//
// windowSize - how many frames to queue, used to bound memory use. Each frame
// takes about 8KB of memory. 25 is a good default, 50 yields higher throughput,
// more than 50 hasn't been seen to have much of an effect.
//
// maxStreamsPerConn - limits the number of streams per physical connection. If
//                     <=0, defaults to max uint32.
//
// pool - BufferPool to use
func StreamDialer(windowSize int, maxStreamsPerConn uint32, pool BufferPool, dial func() (net.Conn, error)) func() (Stream, error) {
	if maxStreamsPerConn <= 0 || maxStreamsPerConn > maxID {
		maxStreamsPerConn = maxID
	}
	d := &dialer{
		doDial:           dial,
		windowSize:       windowSize,
		maxStreamPerConn: maxStreamsPerConn,
		pool:             pool,
	}
	return d.dial
}

type dialer struct {
	doDial           func() (net.Conn, error)
	windowSize       int
	maxStreamPerConn uint32
	pool             BufferPool
	current          *session
	id               uint32
	mx               sync.Mutex
}

func (d *dialer) dial() (Stream, error) {
	d.mx.Lock()
	current := d.current
	idsExhausted := false
	if d.id > d.maxStreamPerConn {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		idsExhausted = true
		d.id = 0
	}

	// TODO: support pooling of connections (i.e. keep multiple physical connections in flight)
	if current == nil || idsExhausted {
		var err error
		current, err = d.startSession()
		if err != nil {
			return nil, err
		}
	}
	id := d.id
	d.id++
	d.mx.Unlock()

	c, _ := current.getOrCreateStream(id)
	return c, nil
}

func (d *dialer) startSession() (*session, error) {
	conn, err := d.doDial()
	if err != nil {
		d.mx.Unlock()
		return nil, err
	}
	sessionStart := make([]byte, sessionStartTotalLen)
	copy(sessionStart, sessionStartBytes)
	sessionStart[sessionStartHeaderLen] = protocolVersion1
	sessionStart[sessionStartHeaderLen+1] = byte(d.windowSize)
	_, writeErr := conn.Write(sessionStart)
	if writeErr != nil {
		conn.Close()
		return nil, writeErr
	}
	d.current = startSession(conn, d.windowSize, d.pool, nil, d.sessionClosed)
	return d.current, nil
}

func (d *dialer) sessionClosed(s *session) {
	d.mx.Lock()
	if d.current == s {
		log.Debug("Current session no longer usable, clearing")
		d.current = nil
	}
	d.mx.Unlock()
}
