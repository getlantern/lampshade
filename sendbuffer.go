package lampshade

import (
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getlantern/ops"
)

var (
	closeTimeout = uint64(30 * time.Second)
)

func getCloseTimeout() time.Duration {
	return time.Duration(atomic.LoadUint64(&closeTimeout))
}

func setCloseTimeout(newTimeout time.Duration) {
	atomic.StoreUint64(&closeTimeout, uint64(newTimeout))
}

// sendBuffer buffers outgoing frames. It holds up to <windowSize> frames,
// after which it starts back-pressuring.
//
// It sends an initial <windowSize> frames. After that, in order to avoid
// filling the receiver's receiveBuffer, it waits for ACKs from the receiver
// before sending new frames.
//
// When closed normally it sends an RST frame to the receiver to indicate that
// the connection is closed. We handle this from sendBuffer so that we can
// ensure buffered frames are sent before sending the RST.
type sendBuffer struct {
	defaultHeader  []byte
	window         *window
	in             chan []byte
	closeOnce      sync.Once
	closeRequested chan bool
	muClosing      sync.RWMutex
	closing        bool
	closed         chan interface{}
}

func newSendBuffer(defaultHeader []byte, out chan []byte, windowSize int) *sendBuffer {
	buf := &sendBuffer{
		defaultHeader:  defaultHeader,
		window:         newWindow(windowSize),
		in:             make(chan []byte, windowSize),
		closeRequested: make(chan bool, 1),
		closed:         make(chan interface{}),
	}
	ops.Go(func() { buf.sendLoop(out) })
	return buf
}

func (buf *sendBuffer) sendLoop(out chan []byte) {
	sendRST := false
	rstFrame := withFrameType(buf.defaultHeader, frameTypeRST)
	closeTimedOut := make(chan interface{})

	var signalCloseOnce sync.Once
	signalClose := func() {
		signalCloseOnce.Do(func() {
			go func() {
				buf.muClosing.Lock()
				buf.closing = true
				close(buf.in)
				buf.muClosing.Unlock()
				time.Sleep(getCloseTimeout())
				close(closeTimedOut)
			}()
		})
	}

	var write func(b []byte)
	write = func(b []byte) {
		select {
		case out <- b:
			// okay
		case sendRST = <-buf.closeRequested:
			// close was requested while we were writing, try again
			signalClose()
			write(b)
		case <-closeTimedOut:
			// closed before frame could be sent, give up
		}
	}

	defer func() {
		if sendRST {
			// Send an RST frame with the streamID
			write(rstFrame)
		}
		close(buf.closed)
	}()

	for {
		select {
		case frame, open := <-buf.in:
			if !open {
				// We've closed
				return
			}
			windowAvailable := buf.window.sub(1)
			select {
			case <-windowAvailable:
				// send allowed
				write(append(frame, buf.defaultHeader...))
			case sendRST = <-buf.closeRequested:
				// close requested before window available
				signalClose()
				select {
				case <-windowAvailable:
					// send allowed
					write(append(frame, buf.defaultHeader...))
				case <-closeTimedOut:
					// closed before window available
					return
				}
			}
		case sendRST = <-buf.closeRequested:
			signalClose()
		case <-closeTimedOut:
			// We had queued writes, but we haven't gotten any acks within
			// closeTimeout of closing, don't wait any longer
			return
		}
	}
}

func (buf *sendBuffer) send(b []byte, writeDeadline time.Time) (int, error) {
	for {
		processed, n, err := buf.doSend(b, writeDeadline)
		if processed {
			return n, err
		}
	}
}

func (buf *sendBuffer) doSend(b []byte, writeDeadline time.Time) (bool, int, error) {
	buf.muClosing.RLock()
	defer buf.muClosing.RUnlock()

	if buf.closing {
		return true, 0, syscall.EPIPE
	}

	closeTimer := time.NewTimer(getCloseTimeout())
	defer closeTimer.Stop()

	if writeDeadline.IsZero() {
		// Don't bother implementing a timeout
		select {
		case buf.in <- b:
			return true, len(b), nil
		case <-closeTimer.C:
			// don't block forever to give us a chance to close
			return false, 0, nil
		}
	}

	now := time.Now()
	if writeDeadline.Before(now) {
		return true, 0, ErrTimeout
	}

	writeTimer := time.NewTimer(writeDeadline.Sub(now))
	defer writeTimer.Stop()

	select {
	case buf.in <- b:
		return true, len(b), nil
	case <-writeTimer.C:
		return true, 0, ErrTimeout
	case <-closeTimer.C:
		// don't block forever to give us a chance to close
		return false, 0, nil
	}
}

func (buf *sendBuffer) close(sendRST bool) {
	buf.closeOnce.Do(func() {
		buf.closeRequested <- sendRST
	})
	<-buf.closed
}
