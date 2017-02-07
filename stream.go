package connmux

import (
	"net"
	"sync"
	"time"
)

// a stream is a multiplexed net.Conn operating on top of a physical net.Conn
// managed by a session.
type stream struct {
	net.Conn
	id            []byte
	session       *session
	pool          BufferPool
	rb            *receiveBuffer
	sb            *sendBuffer
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	finalReadErr  error
	finalWriteErr error
	mx            sync.RWMutex
}

func (c *stream) Read(b []byte) (int, error) {
	c.mx.RLock()
	readDeadline := c.readDeadline
	finalReadErr := c.finalReadErr
	c.mx.RUnlock()
	if finalReadErr != nil {
		return 0, finalReadErr
	}
	return c.rb.read(b, readDeadline)
}

func (c *stream) Write(b []byte) (int, error) {
	if len(b) > MaxDataLen {
		return c.writeChunks(b)
	}

	c.mx.RLock()
	closed := c.closed
	writeDeadline := c.writeDeadline
	finalWriteErr := c.finalWriteErr
	c.mx.RUnlock()
	if finalWriteErr != nil {
		return 0, finalWriteErr
	}
	if closed {
		// Make it look like the write worked even though we're not going to send it
		// anywhere (TODO, might be better way to handle this?)
		return len(b), nil
	}

	// copy buffer since we hang on to it past the call to Write but callers
	// expect that they can reuse the buffer after Write returns
	_b := b
	b = c.pool.getForFrame()[:len(b)]
	copy(b, _b)

	if writeDeadline.IsZero() {
		// Don't bother implementing a timeout
		c.sb.in <- b
		return len(b), nil
	}

	now := time.Now()
	if writeDeadline.Before(now) {
		return 0, ErrTimeout
	}
	timer := time.NewTimer(writeDeadline.Sub(now))
	select {
	case c.sb.in <- b:
		timer.Stop()
		return len(b), nil
	case <-timer.C:
		timer.Stop()
		return 0, ErrTimeout
	}
}

// writeChunks breaks the buffer down into units smaller than MaxDataLen in size
func (c *stream) writeChunks(b []byte) (int, error) {
	totalN := 0
	for {
		toWrite := b
		last := true
		if len(b) > MaxDataLen {
			toWrite = b[:MaxDataLen]
			b = b[MaxDataLen:]
			last = false
		}
		n, err := c.Write(toWrite)
		totalN += n
		if last || err != nil {
			return totalN, err
		}
	}
}

func (c *stream) Close() error {
	return c.close(true, ErrConnectionClosed, ErrConnectionClosed)
}

func (c *stream) close(sendRST bool, readErr error, writeErr error) error {
	didClose := false
	c.mx.Lock()
	if !c.closed {
		c.closed = true
		c.finalReadErr = readErr
		c.finalWriteErr = writeErr
		didClose = true
	}
	c.mx.Unlock()
	if didClose {
		c.rb.close()
		c.sb.close(sendRST)
	}
	return nil
}

func (c *stream) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	c.mx.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mx.Unlock()
	return nil
}

func (c *stream) SetReadDeadline(t time.Time) error {
	c.mx.Lock()
	c.readDeadline = t
	c.mx.Unlock()
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	c.mx.Lock()
	c.writeDeadline = t
	c.mx.Unlock()
	return nil
}

func (c *stream) Session() Session {
	return c.session
}

func (c *stream) Wrapped() net.Conn {
	return c.Session()
}
