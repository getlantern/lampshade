package lampshade

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuffer(t *testing.T) {
	buf := newBuffer()
	p := make([]byte, 1000)
	zeroTime := time.Time{}

	_, err := buf.read(p, time.Now().Add(-1*time.Hour))
	if !assert.Error(t, err, "read from empty buffer with past deadline should fail") {
		return
	}

	_, err = buf.read(p, time.Now().Add(25*time.Millisecond))
	if !assert.Error(t, err, "read from empty buffer with future deadline should fail") {
		return
	}

	buf.write([]byte("a"))
	assert.Equal(t, 1, buf.size)
	n, err := buf.read(p, zeroTime)
	if !assert.NoError(t, err) || !assert.Equal(t, 1, n) {
		return
	}
	assert.Equal(t, "a", string(p[:n]))
	assert.Equal(t, 0, buf.size)

	buf.write([]byte("ab"))
	assert.Equal(t, 2, buf.size)
	buf.write([]byte("c"))
	assert.Equal(t, 3, buf.size)
	n, err = buf.read(p[:1], zeroTime)
	if !assert.NoError(t, err) || !assert.Equal(t, 1, n) {
		return
	}
	assert.Equal(t, 2, buf.size)
	n, err = buf.read(p[1:], zeroTime)
	if !assert.NoError(t, err) || !assert.Equal(t, 2, n) {
		return
	}
	assert.Equal(t, "abc", string(p[:3]))
	assert.Equal(t, 0, buf.size)
}
