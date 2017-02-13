package lampshade

import (
	"sync"
	"time"
)

type buffer struct {
	head   *bufferEntry
	tail   *bufferEntry
	onData chan bool
	size   int
	mx     sync.Mutex
}

type bufferEntry struct {
	data []byte
	next *bufferEntry
}

func newBuffer() *buffer {
	return &buffer{}
}

func (b *buffer) write(p []byte) {
	b.mx.Lock()
	b.doWrite(p)
	b.mx.Unlock()
}

func (b *buffer) doWrite(p []byte) {
	if b.tail == nil {
		b.tail = &bufferEntry{data: p}
		b.head = b.tail
		b.size += len(p)
		return
	}
	b.tail.next = &bufferEntry{data: p}
	b.size++
}

func (b *buffer) read(p []byte, deadline time.Time) (int, error) {
	var now time.Time
	var onData chan bool

	b.mx.Lock()
	n := b.doRead(p)
	if n == 0 {
		now = time.Now()
		if !deadline.IsZero() && deadline.Before(now) {
			b.mx.Unlock()
			return 0, ErrTimeout
		}
		onData = make(chan bool)
		b.onData = onData
	}
	b.mx.Unlock()
	if n > 0 {
		return n, nil
	}
	if deadline.IsZero() {
		// wait indefinitely
		<-onData
		return b.read(p, deadline)
	}
	timeout := time.NewTimer(deadline.Sub(now))
	select {
	case <-onData:
		timeout.Stop()
		return b.read(p, deadline)
	case <-timeout.C:
		timeout.Stop()
		return 0, ErrTimeout
	}
}

func (b *buffer) doRead(p []byte) (totalN int) {
	for {
		if b.head == nil {
			return
		}
		n := copy(p, b.head.data)
		totalN += n
		b.size -= n
		if n < len(b.head.data) {
			b.head.data = b.head.data[n:]
			return
		}
		b.head = b.head.next
		if b.head == nil {
			b.tail = nil
		}
		if n == len(p) {
			return
		}
		p = p[n:]
	}
}
