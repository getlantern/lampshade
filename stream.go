package lampshade

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opentracing/opentracing-go"

	otlog "github.com/opentracing/opentracing-go/log"
)

// a stream is a multiplexed net.Conn operating on top of a physical net.Conn
// managed by a session.
type stream struct {
	net.Conn
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
	id            uint16
	span          opentracing.Span
	upstreamHost  string
}

func newStream(ctx context.Context, s *session, bp BufferPool, w io.Writer, windowSize int, defaultHeader []byte, id uint16, upstreamHost string) *stream {
	atomic.AddInt64(&openStreams, 1)

	// If there is an existing parent span, create a child span. Otherwise do not trace.
	opts := make([]opentracing.StartSpanOption, 0)
	var span opentracing.Span
	if parentSpan := opentracing.SpanFromContext(ctx); parentSpan != nil {
		opts = append(opts, opentracing.ChildOf(parentSpan.Context()))
		span = opentracing.GlobalTracer().StartSpan(fmt.Sprintf("stream-%v-%v", id, upstreamHost), opts...)
	} else {
		noop := opentracing.NoopTracer{}
		span = noop.StartSpan("noop")
	}
	return &stream{
		Conn:         s,
		session:      s,
		pool:         bp,
		sb:           newSendBuffer(defaultHeader, w, windowSize),
		rb:           newReceiveBuffer(defaultHeader, w, bp, windowSize),
		id:           id,
		span:         span,
		upstreamHost: upstreamHost,
	}
}

func (c *stream) Read(b []byte) (int, error) {
	c.mx.RLock()
	readDeadline := c.readDeadline
	finalReadErr := c.finalReadErr
	c.mx.RUnlock()
	if finalReadErr != nil {
		return 0, finalReadErr
	}
	num, err := c.rb.read(b, readDeadline)
	c.span.LogFields(otlog.Int("r", num))
	return num, err
}

func (c *stream) Write(b []byte) (int, error) {
	if len(b) > MaxDataLen {
		return c.writeChunks(b)
	}

	c.mx.RLock()
	writeDeadline := c.writeDeadline
	finalWriteErr := c.finalWriteErr
	c.mx.RUnlock()
	if finalWriteErr != nil {
		return 0, finalWriteErr
	}

	// copy buffer since we hang on to it past the call to Write but callers
	// expect that they can reuse the buffer after Write returns
	_b := b
	b = c.pool.getForFrame()[:len(b)]
	copy(b, _b)
	num, err := c.sb.send(b, writeDeadline)
	c.span.LogFields(otlog.Int("w", num))
	return num, err
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

func (c *stream) ack(frames int) {
	c.sb.window.add(frames)
}

func (c *stream) Close() error {
	return c.close(true, ErrConnectionClosed, ErrConnectionClosed)
}

func (c *stream) close(sendRST bool, readErr error, writeErr error) error {
	c.mx.Lock()
	if !c.closed {
		atomic.AddInt64(&closingStreams, 1)
		c.closed = true
		c.finalReadErr = readErr
		c.finalWriteErr = writeErr
		c.rb.close()
		c.sb.close(sendRST)
		atomic.AddInt64(&closingStreams, -1)
		atomic.AddInt64(&openStreams, -1)
		atomic.AddInt64(&closedStreams, 1)
		c.span.Finish()
	}
	c.mx.Unlock()
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

func (c *stream) String() string {
	c.mx.RLock()
	str := fmt.Sprintf("Lampshade stream: {id: %v, stream: %#v, session: %v}", int(c.id), c, c.session.String())
	c.mx.RUnlock()
	return str
}
