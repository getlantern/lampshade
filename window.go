package lampshade

import (
	"sync"
	"time"
)

var (
	immediate chan bool
)

func init() {
	close(immediate)
}

// window models a flow-control window
type window struct {
	size          int
	positiveAgain chan bool
	closed        bool
	mx            sync.Mutex
}

func newWindow(initial int) *window {
	return &window{
		size:          initial,
		positiveAgain: make(chan bool),
	}
}

// add adds to the window
func (w *window) add(delta int) {
	w.mx.Lock()
	wasNegative := w.size < 0
	w.size += delta
	isNegative := w.size < 0
	shouldSignal := wasNegative && !isNegative
	w.mx.Unlock()
	if shouldSignal {
		select {
		case w.positiveAgain <- true:
			// ok
		default:
			// nobody waiting anymore
		}
	}
}

// sub subtracts from the window and blocks until the window is large enough to
// subtract the given delta while still leaving a non-zero window size.
func (w *window) sub(delta int, deadline time.Time) error {
	w.mx.Lock()
	w.size -= delta
	isNegative := w.size < 0
	w.mx.Unlock()
	if !isNegative {
		return nil
	}

	// window negative, need to wait for it to become positive again
	if deadline.IsZero() {
		// block indefinitely
		<-w.positiveAgain
		return nil
	}
	now := time.Now()
	if deadline.Before(now) {
		// already passed deadline
		return w.timedOut(delta)
	}
	// block until deadline
	t := time.NewTimer(deadline.Sub(now))
	select {
	case <-w.positiveAgain:
		t.Stop()
		return nil
	case <-t.C:
		t.Stop()
		return w.timedOut(delta)
	}
}

func (w *window) timedOut(delta int) error {
	// undo the subtraction
	w.add(delta)
	// record the timeout
	return ErrTimeout
}

func (w *window) close() {
	w.mx.Lock()
	shouldClose := !w.closed
	w.closed = true
	w.mx.Unlock()
	if shouldClose {
		select {
		case <-w.positiveAgain:
			// drained
		default:
			// nothing to drain
		}
		close(w.positiveAgain)
	}
}
