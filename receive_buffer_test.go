package lampshade

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReceiveBuffer(t *testing.T) {
	header := newHeader(frameTypeData, 27)

	depth := 5

	pool := &testpool{}
	ack := make(chan []byte, 1000)
	buf := newReceiveBuffer(header, ack, pool, depth)
	for i := 0; i < 2; i++ {
		b := pool.Get()
		b[dataHeaderSize] = fmt.Sprint(i)[0]
		buf.submit(b[:dataHeaderSize+1])
	}

	b := make([]byte, 2)
	n, err := buf.read(b, time.Time{})
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, 2, n)
	assert.Equal(t, "01", string(b[:n]))
	assert.Equal(t, maxFrameSize, pool.getTotalReturned(), "Failed to return first buffer to pool")

	totalAcks := 0
ackloop:
	for {
		select {
		case a := <-ack:
			if assert.EqualValues(t, frameTypeACK, a[winSize]) {
				a2 := withFrameType(a[winSize:], frameTypeData)
				if assert.EqualValues(t, header, a2) {
					totalAcks++
				}
			}
		default:
			break ackloop
		}
	}
	assert.Equal(t, 2, totalAcks)
}

type testpool struct {
	totalReturned int64
}

func (tp *testpool) getForFrame() []byte {
	return make([]byte, maxFrameSize)
}

func (tp *testpool) Get() []byte {
	return make([]byte, MaxDataLen, maxFrameSize)
}

func (tp *testpool) Put(b []byte) {
	atomic.AddInt64(&tp.totalReturned, int64(len(b)))
}

func (tp *testpool) getTotalReturned() int {
	return int(atomic.LoadInt64(&tp.totalReturned))
}
