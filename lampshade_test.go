package lampshade

import (
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/getlantern/keyman"
	"github.com/getlantern/tlsdefaults"
	"github.com/stretchr/testify/assert"
)

const (
	testdata = "Hello Dear World"

	windowSize = 4
	maxPadding = 32

	testPingInterval = 15 * time.Millisecond
)

var (
	largeData = make([]byte, MaxDataLen)
)

func init() {
	rand.Read(largeData)
}

func TestConnMultiplex(t *testing.T) {
	doTestConnBasicFlow(t)
}

func TestWriteSplitting(t *testing.T) {
	multiplier := 10000
	size := len(testdata) * multiplier
	reallyBigData := make([]byte, 0, size)
	for i := 0; i < multiplier; i++ {
		reallyBigData = append(reallyBigData, testdata...)
	}

	l, _, dial, wg, err := echoServerAndDialer(0)
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
	l, _, dial, wg, err := echoServerAndDialer(0)
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
	l, _, dial, _, err := echoServerAndDialer(0)
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
	l, _, dial, _, err := echoServerAndDialer(0)
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
	l, _, dial, _, err := echoServerAndDialer(0)
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
	l, _, dial, _, err := echoServerAndDialer(uint16(max))
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

func doTestConnBasicFlow(t *testing.T) {
	l, dialer, dial, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	time.Sleep(2 * testPingInterval)

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

	assert.True(t, dialer.EMARTT() > 0)
}

func echoServerAndDialer(maxStreamsPerConn uint16) (net.Listener, Dialer, DialFN, *sync.WaitGroup, error) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	wrapped, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pkFile, certFile := "pkfile.pem", "certfile.pem"
	wrapped, err = tlsdefaults.NewListener(wrapped, pkFile, certFile)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pool := NewBufferPool(100)
	l := WrapListener(wrapped, pool, pk.RSA())

	var wg sync.WaitGroup
	go func() {
	acceptLoop:
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				log.Errorf("Unable to accept connection: %v", acceptErr)
				switch t := acceptErr.(type) {
				case net.Error:
					if t.Temporary() {
						continue acceptLoop
					}
				}
				return
			}

			wg.Add(1)
			go func() {
				defer conn.Close()
				defer wg.Done()

				b := make([]byte, 4)
				total := 0
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
					total += n
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

	doDial := func() (net.Conn, error) {
		return tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	dialer := NewDialer(&DialerOpts{
		WindowSize:        windowSize,
		MaxPadding:        maxPadding,
		MaxStreamsPerConn: maxStreamsPerConn,
		PingInterval:      testPingInterval,
		Pool:              pool,
		Cipher:            AES128GCM,
		ServerPublicKey:   &pk.RSA().PublicKey})

	return l, dialer, func() (net.Conn, error) {
		return dialer.Dial(doDial)
	}, &wg, nil
}

func TestConcurrency(t *testing.T) {
	concurrency := 100

	pk, err := keyman.GeneratePK(2048)
	if !assert.NoError(t, err) {
		return
	}

	pool := NewBufferPool(concurrency * windowSize * 3)
	_lst, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Unable to listen: %v", err)
	}
	lst := WrapListener(_lst, pool, pk.RSA())

	go func() {
		for {
			conn, err := lst.Accept()
			if err != nil {
				t.Fatalf("Unable to accept: %v", err)
			}
			go func() {
				io.Copy(conn, conn)
			}()
		}
	}()

	dial := NewDialer(
		&DialerOpts{
			WindowSize:      windowSize,
			MaxPadding:      maxPadding,
			IdleInterval:    15 * time.Millisecond,
			Pool:            NewBufferPool(100),
			Cipher:          ChaCha20Poly1305,
			ServerPublicKey: &pk.RSA().PublicKey}).Dial
	doDial := func() (net.Conn, error) {
		return net.Dial("tcp", lst.Addr().String())
	}
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			conn, err := dial(doDial)
			if !assert.NoError(t, err) {
				t.Fatal("Can't dial")
			}
			defer conn.Close()
			go feed(t, conn)

			b := make([]byte, windowSize*3*MaxDataLen)
			totalN := 0
			for {
				n, err := conn.Read(b[totalN:])
				if !assert.NoError(t, err) {
					t.Fatalf("Unable to read: %v", err)
				}
				totalN += n
				if totalN == windowSize*3*MaxDataLen {
					for i := 0; i < 3; i++ {
						assert.EqualValues(t, largeData[i*windowSize:i*windowSize*2], string(b[i*windowSize:i*windowSize*2]))
					}
					return
				}
			}
		}()
	}

	wg.Wait()
}

func feed(t *testing.T, conn net.Conn) {
	for i := 0; i < windowSize*3; i++ {
		_, err := conn.Write(largeData)
		if err != nil {
			t.Fatal("Unable to feed")
		}
	}
}

func BenchmarkThroughputLampshadeNoEncryption(b *testing.B) {
	doBenchmarkThroughputLampshade(b, NoEncryption)
}

func BenchmarkThroughputLampshadeAES128GCM(b *testing.B) {
	doBenchmarkThroughputLampshade(b, AES128GCM)
}

func BenchmarkThroughputLampshadeChaCha20Poly1305(b *testing.B) {
	doBenchmarkThroughputLampshade(b, ChaCha20Poly1305)
}

func doBenchmarkThroughputLampshade(b *testing.B, cipherCode Cipher) {
	f, err := os.Create(cipherCode.String() + ".cpuprofile")
	if err != nil {
		b.Fatal("could not create CPU profile: ", err)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		b.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		b.Fatal(err)
	}

	_lst, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	lst := WrapListener(_lst, NewBufferPool(100), pk.RSA())

	conn, err := NewDialer(&DialerOpts{
		WindowSize:      25,
		MaxPadding:      maxPadding,
		Pool:            NewBufferPool(100),
		Cipher:          cipherCode,
		ServerPublicKey: &pk.RSA().PublicKey}).Dial(func() (net.Conn, error) {
		return net.Dial("tcp", lst.Addr().String())
	})
	if err != nil {
		b.Fatal(err)
	}

	doBench(b, lst, conn)
}

func BenchmarkThroughputTCP(b *testing.B) {
	f, err := os.Create("tcp.cpuprofile")
	if err != nil {
		b.Fatal("could not create CPU profile: ", err)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		b.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	lst, err := net.Listen("tcp", ":0")
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
