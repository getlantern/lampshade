package lampshade

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSendBuffer(t *testing.T) {
	header := newHeader(frameTypeData, 27)

	depth := 5

	out := make(chan []byte)
	buf := newSendBuffer(header, out, depth)

	// write loop
	go func() {
		defer buf.close(false)
		for i := 0; i < 10; i++ {
			buf.in <- []byte(fmt.Sprint(i))
		}
	}()

	// Make sure we got correct stuff
	wrote := ""
loop:
	for {
		select {
		case b := <-out:
			if assert.EqualValues(t, header, b[1:]) {
				wrote += string(b[:1])
			}
		case <-time.After(25 * time.Millisecond):
			break loop
		}
	}
	assert.Equal(t, "01234", string(wrote))

	// Simulate ACK
	buf.window.add(depth)
	// Make sure we got correct stuff
loop2:
	for {
		select {
		case b := <-out:
			if assert.EqualValues(t, header, b[1:]) {
				wrote += string(b[:1])
			}
		case <-time.After(25 * time.Millisecond):
			break loop2
		}
	}
	assert.Equal(t, "0123456789", string(wrote))
}
