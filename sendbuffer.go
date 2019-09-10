package lampshade

import (
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/ops"
)

var (
	closeTimeout = 30 * time.Second
)

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
	closeRequested chan bool
	muClosing      sync.RWMutex
	closing        bool
	closed         sync.WaitGroup
	writeTimer     *time.Timer
	lifecycle      StreamLifecycleListener
}

func newSendBuffer(defaultHeader []byte, w io.Writer, windowSize int, lifecycle StreamLifecycleListener) *sendBuffer {
	buf := &sendBuffer{
		defaultHeader:  defaultHeader,
		window:         newWindow(windowSize),
		in:             make(chan []byte, windowSize),
		closeRequested: make(chan bool, 1),
		writeTimer:     time.NewTimer(largeTimeout),
		lifecycle:      lifecycle,
	}
	buf.closed.Add(1)
	ops.Go(func() { buf.sendLoop(w) })
	return buf
}

func (buf *sendBuffer) sendLoop(w io.Writer) {
	sendRST := false
	defer func() {
		if sendRST {
			// Send an RST frame with the streamID
			w.Write(withFrameType(buf.defaultHeader, frameTypeRST))
		}
		// drain remaining writes
		for range buf.in {
		}
		buf.closed.Done()
	}()

	closeTimedOut := make(chan interface{})
	var closeOnce sync.Once
	signalClose := func() {
		closeOnce.Do(func() {
			go func() {
				buf.muClosing.Lock()
				buf.closing = true
				close(buf.in)
				buf.muClosing.Unlock()
				time.Sleep(closeTimeout)
				close(closeTimedOut)
			}()
		})
	}

	for {
		select {
		case frame, open := <-buf.in:
			if frame != nil {
				windowAvailable := buf.window.sub(1)
				select {
				case <-windowAvailable:
					// send allowed
					w.Write(append(frame, buf.defaultHeader...))
				case sendRST = <-buf.closeRequested:
					// close requested before window available
					signalClose()
					select {
					case <-windowAvailable:
						// send allowed
						w.Write(append(frame, buf.defaultHeader...))
					case <-closeTimedOut:
						// closed before window available
						return
					}
				}
			}
			if !open {
				// We've closed
				return
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
	buf.muClosing.RLock()
	n, err := buf.doSend(b, writeDeadline)
	buf.muClosing.RUnlock()
	if err != nil {
		buf.lifecycle.OnStreamWrite(n)
	} else {
		buf.lifecycle.OnStreamWriteError(err)
	}
	return n, err
}

func (buf *sendBuffer) doSend(b []byte, writeDeadline time.Time) (int, error) {
	if buf.closing {
		return 0, syscall.EPIPE
	}

	if writeDeadline.IsZero() {
		// Don't bother implementing a timeout
		buf.in <- b
		return len(b), nil
	}

	now := time.Now()
	if writeDeadline.Before(now) {
		err := newErrTimeout("writing after deadline passed")
		return 0, err
	}
	if !buf.writeTimer.Stop() {
		<-buf.writeTimer.C
	}
	delay := writeDeadline.Sub(now)
	buf.writeTimer.Reset(delay)
	select {
	case buf.in <- b:
		return len(b), nil
	case <-buf.writeTimer.C:
		err := newErrTimeoutWithTime("write timer fired", delay)
		return 0, err
	}
}

func (buf *sendBuffer) close(sendRST bool) {
	select {
	case buf.closeRequested <- sendRST:
		// okay
	default:
		// close already requested, ignore
	}
	buf.writeTimer.Stop()
	buf.closed.Wait()
}
