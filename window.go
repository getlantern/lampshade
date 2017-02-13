package lampshade

import (
	"sync"
)

var (
	immediate = make(chan bool)
)

func init() {
	close(immediate)
}

// window models a flow-control window
type window struct {
	size          int
	positiveAgain chan bool
	closeCh       chan bool
	closed        bool
	mx            sync.Mutex
}

func newWindow(initial int) *window {
	return &window{
		size:          initial,
		positiveAgain: make(chan bool),
		closeCh:       make(chan bool),
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
		case <-w.closeCh:
			// nobody waiting anymore
		}
	}
}

// sub subtracts from the window and returns a channel that blocks until the
// window is large enough to subtract the given delta while still leaving a
// non-zero window size.
func (w *window) sub(delta int) chan bool {
	w.mx.Lock()
	w.size -= delta
	isNegative := w.size < 0
	w.mx.Unlock()
	if !isNegative {
		return immediate
	}
	return w.positiveAgain
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
		close(w.closeCh)
		select {
		case <-w.positiveAgain:
			// drained
		default:
			// nothing to drain
		}
		close(w.positiveAgain)
	}
}
