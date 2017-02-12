package lampshade

import (
	"net"
	"sync"
	"time"
)

// a stream is a multiplexed net.Conn operating on top of a physical net.Conn
// managed by a session.
type stream struct {
	net.Conn
	session       *session
	window        *window
	defaultHeader []byte
	rb            *receiveBuffer
	pendingWrite  chan []byte
	writeResponse chan error
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
	c.mx.RLock()
	closed := c.closed
	writeDeadline := c.writeDeadline
	finalWriteErr := c.finalWriteErr
	if finalWriteErr != nil {
		c.mx.RUnlock()
		return 0, finalWriteErr
	}
	if closed {
		c.mx.RUnlock()
		return 0, ErrConnectionClosed
	}

	// Wait for transmit window availability
	log.Debugf("Waiting for %d", len(b))
	err := c.window.sub(len(b), writeDeadline)
	log.Debug("Available!")
	if err != nil {
		c.mx.RUnlock()
		return 0, err
	}

	result := func(err error) (int, error) {
		c.mx.RUnlock()
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	if writeDeadline.IsZero() {
		// Don't bother implementing a timeout
		c.pendingWrite <- append(b, c.defaultHeader...)
		err := <-c.writeResponse
		return result(err)
	}

	now := time.Now()
	if writeDeadline.Before(now) {
		return 0, ErrTimeout
	}
	timer := time.NewTimer(writeDeadline.Sub(now))

	stopTimerResult := func(err error) (int, error) {
		timer.Stop()
		return result(err)
	}

	select {
	case c.pendingWrite <- b:
		select {
		case err := <-c.writeResponse:
			return stopTimerResult(err)
		case <-timer.C:
			return stopTimerResult(ErrTimeout)
		}
	case <-timer.C:
		return stopTimerResult(ErrTimeout)
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
		c.window.close()
		// TODO: handle sending RST
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
