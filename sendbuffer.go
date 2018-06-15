package lampshade

import (
	"io"
	"sync"
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
}

func newSendBuffer(defaultHeader []byte, w io.Writer, windowSize int) *sendBuffer {
	buf := &sendBuffer{
		defaultHeader:  defaultHeader,
		window:         newWindow(windowSize),
		in:             make(chan []byte, windowSize),
		closeRequested: make(chan bool, 1),
		writeTimer:     time.NewTimer(largeTimeout),
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

	closeTimer := time.NewTimer(largeTimeout)
	signalClose := func() {
		buf.muClosing.Lock()
		buf.closing = true
		close(buf.in)
		buf.muClosing.Unlock()
		closeTimer.Reset(closeTimeout)
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
					go signalClose()
					select {
					case <-windowAvailable:
						// send allowed
						w.Write(append(frame, buf.defaultHeader...))
					case <-closeTimer.C:
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
			go signalClose()
		case <-closeTimer.C:
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
	return n, err
}

func (buf *sendBuffer) doSend(b []byte, writeDeadline time.Time) (int, error) {
	if buf.closing {
		// Make it look like the write worked even though we're not going to send it
		// anywhere (TODO, might be better way to handle this?)
		return len(b), nil
	}

	if writeDeadline.IsZero() {
		// Don't bother implementing a timeout
		buf.in <- b
		return len(b), nil
	}

	now := time.Now()
	if writeDeadline.Before(now) {
		return 0, ErrTimeout
	}
	buf.writeTimer.Reset(writeDeadline.Sub(now))
	select {
	case buf.in <- b:
		return len(b), nil
	case <-buf.writeTimer.C:
		return 0, ErrTimeout
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
