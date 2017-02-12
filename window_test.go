package lampshade

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWindow(t *testing.T) {
	w := newWindow(10)

	subtracted := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer w.close()
		defer w.close()
		defer wg.Done()

		for subtracted < 30 {
			<-w.sub(3)
			subtracted += 3
		}
	}()

	for i := 0; i < 20; i++ {
		w.add(1)
	}

	wg.Wait()
	assert.Equal(t, 30, subtracted)
}
