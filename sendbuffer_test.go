package connmux

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSendBuffer(t *testing.T) {
	id := make([]byte, idLen)
	binaryEncoding.PutUint32(id, 27)

	depth := 5

	out := make(chan []byte)
	buf := newSendBuffer(id, out, depth)
	defer buf.close(false)

	var mx sync.RWMutex
	wrote := ""
	closed := false
	go func() {
		for b := range out {
			if assert.EqualValues(t, id, b[1:]) {
				mx.Lock()
				wrote += string(b[:1])
				mx.Unlock()
			}
		}
		mx.Lock()
		closed = true
		mx.Unlock()
	}()

	// Should be able to write to twice depth with no problem
	for i := 0; i < 2*depth; i++ {
		buf.in <- []byte(fmt.Sprint(i))
	}

	// Writing past depth should fail
	select {
	case buf.in <- []byte("fail"):
		assert.Fail(t, "Writing past buffer depth should have failed")
		return
	default:
		// good
	}

	time.Sleep(25 * time.Millisecond)
	// Make sure we got correct stuff
	mx.RLock()
	_wrote := wrote
	mx.RUnlock()
	assert.Equal(t, "01234", string(_wrote))

	// Make sure we can ack up to depth
	for i := 0; i < depth; i++ {
		select {
		case buf.ack <- true:
			// good
		default:
			assert.Fail(t, "Failed to ack to buffer on iteration %d", i)
			return
		}
	}

	time.Sleep(25 * time.Millisecond)
	// Make sure we got correct stuff after additional acks
	mx.RLock()
	_wrote = wrote
	mx.RUnlock()
	assert.Equal(t, "0123456789", string(_wrote))
}
