package lampshade

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWindow(t *testing.T) {
	w := newWindow(10)

	err := w.sub(10, time.Now().Add(-5*time.Millisecond))
	if !assert.NoError(t, err, "Subtracting initial capacity should have worked") {
		return
	}

	err = w.sub(3, time.Now().Add(25*time.Millisecond))
	if !assert.Error(t, err, "Overdrawing with deadline in past should have timed out") {
		return
	}

	err = w.sub(3, time.Now().Add(25*time.Millisecond))
	if !assert.Error(t, err, "Overdrawing with deadline in future should have timed out") {
		return
	}

	subtracted := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer w.close()
		defer w.close()
		defer wg.Done()

		for subtracted < 30 {
			err := w.sub(3, time.Now().Add(1*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			subtracted += 3
		}
	}()

	for i := 0; i < 30; i++ {
		w.add(1)
	}

	wg.Wait()
	assert.Equal(t, 30, subtracted)
}
