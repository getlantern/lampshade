package lampshade

import (
	"io"
	"math"
	"sync"
	"time"
)

// receiveBuffer buffers incoming frames. It queues up available frames in a
// channel and makes sure that those are read in order when filling reader's
// buffers via the read() method. It also makes sure to send an ack whenever a
// queued frame has been fully read.
//
// In order to bound memory usage, the channel holds only <windowSize> frames,
// after which it starts back-pressuring. The sender knows not to send more
// than <windowSize> frames so as to prevent this. Once the sender receives an
// ACK from the receiver, it sends a subsequent frame and so on.
type receiveBuffer struct {
	defaultHeader []byte
	windowSize    int
	ackInterval   int
	unacked       int
	in            chan []byte
	ack           chan []byte
	pool          BufferPool
	poolable      []byte
	current       []byte
	muClosing     sync.RWMutex
	closed        chan interface{}
}

func newReceiveBuffer(defaultHeader []byte, ack chan []byte, pool BufferPool, windowSize int) *receiveBuffer {
	ackInterval := int(math.Ceil(float64(windowSize) / 10))
	return &receiveBuffer{
		defaultHeader: defaultHeader,
		windowSize:    windowSize,
		ackInterval:   ackInterval,
		in:            make(chan []byte, windowSize),
		ack:           ack,
		pool:          pool,
		closed:        make(chan interface{}),
	}
}

// submit allows the session to submit a new frame to the receiveBuffer. If the
// receiveBuffer has been closed, this is a noop.
func (buf *receiveBuffer) submit(frame []byte) {
	for {
		if buf.doSubmit(frame) {
			return
		}
	}
}

func (buf *receiveBuffer) doSubmit(frame []byte) bool {
	buf.muClosing.RLock()
	defer buf.muClosing.RUnlock()

	select {
	case <-buf.closed:
		// already closed, don't bother
		return true
	default:
		closeTimer := time.NewTimer(getCloseTimeout())
		defer closeTimer.Stop()

		select {
		case buf.in <- frame:
			// okay
			return true
		case <-closeTimer.C:
			// don't block forever on writing to buf.in. This gives us a chance to see whether we've closed in the meantime
			return false
		}
	}
}

// reads available data into the given buffer. If no data is queued, read will
// wait up to deadline to receive some data. If deadline is Zero, read will wait
// indefinitely for new data.
//
// As long as some data was already queued, read will not wait for more data
// even if b has not yet been filled.
func (buf *receiveBuffer) read(b []byte, deadline time.Time) (totalN int, err error) {
	for {
		n := copy(b, buf.current)
		buf.current = buf.current[n:]
		totalN += n
		if n == len(b) {
			// nothing more to copy
			buf.ackIfNecessary()
			return
		}

		// b can hold more than we had in the current slice, try to read more if
		// immediately available.
		b = b[n:]
		select {
		case frame, open := <-buf.in:
			// Read next frame, continue loop
			if !open {
				// we've hit the end
				err = io.EOF
				buf.ackIfNecessary()
				return
			}
			buf.onFrame(frame)
			continue
		default:
			// nothing immediately available
			if totalN > 0 {
				// we've read something, return what we have
				buf.ackIfNecessary()
				return
			}

			// We haven't ready anything, wait up till deadline to read
			now := time.Now()
			if deadline.IsZero() {
				// Default deadline to something really large so that we effectively
				// don't time out.
				deadline = largeDeadline
			} else if deadline.Before(now) {
				// Deadline already past, don't bother doing anything
				buf.ackIfNecessary()
				return
			}

			readTimer := time.NewTimer(deadline.Sub(now))
			select {
			case <-readTimer.C:
				// Nothing read within deadline
				err = ErrTimeout
				buf.ackIfNecessary()
				return
			case frame, open := <-buf.in:
				// Read next frame, continue loop
				readTimer.Stop()
				if !open {
					// we've hit the end
					err = io.EOF
					buf.ackIfNecessary()
					return
				}
				buf.onFrame(frame)
				continue
			}
		}
	}
}

// ackIfNecessary acks every buf.ackInterval
func (buf *receiveBuffer) ackIfNecessary() {
	if buf.unacked >= buf.ackInterval {
		buf.doSendACK(buf.unacked)
		buf.unacked = 0
	}
}

func (buf *receiveBuffer) doSendACK(unacked int) {
	select {
	case <-buf.closed:
		return
	case buf.ack <- ackWithFrames(buf.defaultHeader, int32(unacked)):
		// okay
	}
}

func (buf *receiveBuffer) onFrame(frame []byte) {
	if buf.poolable != nil {
		// Return previous frame to pool
		buf.pool.Put(buf.poolable[:maxFrameSize])
	}
	buf.poolable = frame
	buf.current = frame[dataHeaderSize:]
	buf.unacked++
}

func (buf *receiveBuffer) close() {
	select {
	case <-buf.closed:
		return
	default:
		buf.muClosing.Lock()
		close(buf.closed)
		close(buf.in)
		buf.muClosing.Unlock()
	}
}
