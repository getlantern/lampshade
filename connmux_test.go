package connmux

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/stretchr/testify/assert"
)

const (
	testdata = "Hello Dear World"

	windowSize = 2
)

func TestConnNoMultiplex(t *testing.T) {
	doTestConnBasicFlow(t, false)
}

func TestConnMultiplex(t *testing.T) {
	doTestConnBasicFlow(t, true)
}

func TestWriteSplitting(t *testing.T) {
	multiplier := 10000
	size := len(testdata) * multiplier
	reallyBigData := make([]byte, 0, size)
	for i := 0; i < multiplier; i++ {
		reallyBigData = append(reallyBigData, testdata...)
	}

	l, dial, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		// Read on a separate goroutine to unblock buffers
		defer wg2.Done()
		b := make([]byte, size)
		n, readErr := io.ReadFull(conn, b)
		if !assert.NoError(t, readErr) {
			return
		}
		assert.Equal(t, size, n)
		assert.Equal(t, string(reallyBigData), string(b[:n]))
	}()

	n, err := conn.Write(reallyBigData)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, size, n)

	wg2.Wait()
	conn.Close()
	wg.Wait()
}

func TestStreamCloseRemoteAfterEcho(t *testing.T) {
	l, dial, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("stop"))
	if !assert.NoError(t, err) {
		return
	}

	time.Sleep(50 * time.Millisecond)
	b := make([]byte, 4)
	n, err := io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "stop", string(b[:n]))

	// Try to read again, should get EOF
	n, err = conn.Read(b)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)

	_, err = conn.Write([]byte("whatever"))
	assert.NoError(t, err, "We got an EOF on read, but writing should still work")

	wg.Wait()
}

func TestPhysicalConnCloseRemotePrematurely(t *testing.T) {
	l, dial, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("kill"))
	if !assert.NoError(t, err) {
		return
	}

	b := make([]byte, 4)
	n, err := conn.Read(b)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)

	_, err = conn.Write([]byte("whatever"))
	assert.Equal(t, ErrBrokenPipe, err)

	// Now dial again and make sure that works
	conn, err = dial()
	if !assert.NoError(t, err) {
		return
	}

	_, err = conn.Write([]byte(testdata))
	if !assert.NoError(t, err) {
		return
	}

	b = make([]byte, len(testdata))
	n, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, testdata, string(b[:n]))
}

func TestStreamCloseLocalPrematurely(t *testing.T) {
	l, dial, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	// Close stream immediately
	conn.Close()

	_, err = conn.Write([]byte("stop"))
	assert.Equal(t, ErrConnectionClosed, err)

	b := make([]byte, 4)
	n, err := conn.Read(b)
	assert.Equal(t, ErrConnectionClosed, err)
	assert.Equal(t, 0, n)
}

func TestPhysicalConnCloseLocalPrematurely(t *testing.T) {
	l, dial, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	// Close physical connection immediately
	conn.(Stream).Session().Close()
	time.Sleep(50 * time.Millisecond)

	_, err = conn.Write([]byte("stop"))
	assert.Equal(t, ErrBrokenPipe, err)

	b := make([]byte, 4)
	n, err := conn.Read(b)
	assert.Error(t, err)
	assert.Equal(t, 0, n)

	// Now dial again and make sure that works
	conn, err = dial()
	if !assert.NoError(t, err) {
		return
	}

	_, err = conn.Write([]byte(testdata))
	if !assert.NoError(t, err) {
		return
	}

	b = make([]byte, len(testdata))
	n, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, testdata, string(b[:n]))
}

func TestConnIDExhaustion(t *testing.T) {
	max := 100
	l, dial, _, err := echoServerAndDialer(uint32(max))
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	_, connCount, err := fdcount.Matching("TCP")
	if !assert.NoError(t, err) {
		return
	}

	for i := 0; i <= max; i++ {
		conn, dialErr := dial()
		if !assert.NoError(t, dialErr) {
			return
		}
		defer conn.Close()
	}

	assert.NoError(t, connCount.AssertDelta(2), "Opening up to MaxID should have resulted in 1 connection (2 TCP sockets including server end)")

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	assert.NoError(t, connCount.AssertDelta(4), "Opening past MaxID should have resulted in 2 connections (4 TCP sockets including server end)")
}

func doTestConnBasicFlow(t *testing.T, mux bool) {
	l, dial, wg, err := doEchoServerAndDialer(mux, 0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	n, err := conn.Write([]byte(testdata))
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Equal(t, len(testdata), n) {
		return
	}

	b := make([]byte, len(testdata))
	n, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Equal(t, len(testdata), n) {
		return
	}

	assert.Equal(t, testdata, string(b))
	conn.Close()
	wg.Wait()
}

func echoServerAndDialer(maxStreamsPerConn uint32) (net.Listener, func() (net.Conn, error), *sync.WaitGroup, error) {
	return doEchoServerAndDialer(true, maxStreamsPerConn)
}

func doEchoServerAndDialer(mux bool, maxStreamsPerConn uint32) (net.Listener, func() (net.Conn, error), *sync.WaitGroup, error) {
	wrapped, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, nil, err
	}

	pool := NewBufferPool(100)
	l := WrapListener(wrapped, pool)

	var wg sync.WaitGroup
	go func() {
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				log.Errorf("Unable to accept connection: %v", acceptErr)
				return
			}

			wg.Add(1)
			go func() {
				defer conn.Close()
				defer wg.Done()

				b := make([]byte, 4)
				for {
					n, readErr := conn.Read(b)
					if readErr != nil && readErr != io.EOF {
						log.Errorf("Error reading for echo: %v", readErr)
						return
					}
					if string(b) == "kill" {
						// Interrupt the underlying connection to see what happens
						conn.(Stream).Session().Close()
						return
					}
					_, writeErr := conn.Write(b[:n])
					if writeErr != nil {
						log.Errorf("Error writing for echo: %v", writeErr)
						return
					}
					if readErr == io.EOF {
						return
					}
					if string(b) == "stop" {
						return
					}
				}
			}()
		}
	}()

	dialer := func() (net.Conn, error) {
		return net.Dial("tcp", l.Addr().String())
	}

	if mux {
		dialer = Dialer(windowSize, maxStreamsPerConn, pool, dialer)
	}

	return l, dialer, &wg, nil
}

func TestConcurrency(t *testing.T) {
	concurrency := 100

	pool := NewBufferPool(concurrency * windowSize * 3)
	_lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to listen: %v", err)
	}
	lst := WrapListener(_lst, pool)

	var wg sync.WaitGroup
	wg.Add(concurrency)

	go func() {
		for {
			conn, err := lst.Accept()
			if err != nil {
				t.Fatalf("Unable to accept: %v", err)
			}
			go func() {
				echo(t, conn, pool)
				wg.Done()
			}()
		}
	}()

	dial := Dialer(windowSize, 0, NewBufferPool(100), func() (net.Conn, error) {
		return net.Dial("tcp", lst.Addr().String())
	})

	var conns []net.Conn
	for i := 0; i < concurrency; i++ {
		conn, err := dial()
		if !assert.NoError(t, err) {
			t.Fatal("Can't dial")
		}
		conns = append(conns, conn)
		go feed(t, conn)
	}

	for _, conn := range conns {
		b := make([]byte, 50)
		totalN := 0
		for {
			n, err := conn.Read(b[totalN:])
			if !assert.NoError(t, err) {
				t.Fatalf("Unable to read: %v", err)
			}
			totalN += n
			if totalN == 10 {
				assert.Equal(t, "0123456789", string(b[:totalN]))
				break
			}
		}

	}

	for _, conn := range conns {
		conn.Close()
	}

	wg.Wait()
}

func echo(t *testing.T, conn net.Conn, pool BufferPool) {
	defer conn.Close()
	b := make([]byte, MaxDataLen)
	for {
		n, err := conn.Read(b)
		if err == io.EOF {
			// Done
			return
		}
		if !assert.NoError(t, err) {
			t.Fatal("Unable to read for echo")
		}
		_, err = conn.Write(b[:n])
		if !assert.NoError(t, err) {
			t.Fatal("Unable to echo")
		}
	}
}

func feed(t *testing.T, conn net.Conn) {
	for i := 0; i < 10; i++ {
		_, err := conn.Write([]byte(fmt.Sprint(i)))
		if err != nil {
			t.Fatal("Unable to feed")
		}
	}
}

func BenchmarkConnMux(b *testing.B) {
	_lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	lst := WrapListener(_lst, NewBufferPool(100))

	conn, err := Dialer(25, 0, NewBufferPool(100), func() (net.Conn, error) {
		return net.Dial("tcp", lst.Addr().String())
	})()
	if err != nil {
		b.Fatal(err)
	}

	doBench(b, lst, conn)
}

func BenchmarkTCP(b *testing.B) {
	lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	conn, err := net.Dial("tcp", lst.Addr().String())
	if err != nil {
		b.Fatal(err)
	}

	doBench(b, lst, conn)
}

func doBench(b *testing.B, l net.Listener, wr io.Writer) {
	pool := NewBufferPool(10)
	buf := pool.Get()
	buf2 := pool.getForFrame()
	b.SetBytes(MaxDataLen)
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		for {
			n, err := conn.Read(buf2)
			if err != nil {
				b.Fatal(err)
			}
			count += n
			if count == MaxDataLen*b.N {
				return
			}
		}
	}()
	for i := 0; i < b.N; i++ {
		_, err := wr.Write(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
	wg.Wait()
}
