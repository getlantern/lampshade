package lampshade

import (
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
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

func init() {
	ReadTimeout = 500 * time.Millisecond
}

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

	l, dialer, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
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
	l, dialer, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
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

	n, err = conn.Write([]byte("whatever"))
	assert.Equal(t, syscall.EPIPE, err, "Writing to the connection after the remote end already closed it should fail with an EPIPE")
	assert.Equal(t, 0, n)

	wg.Wait()
}

func TestPhysicalConnCloseRemotePrematurely(t *testing.T) {
	l, dialer, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
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
	conn, err = dialer.Dial()
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
	l, dialer, _, err := echoServerAndDialerWithIdleInterval(0, 5000000, 0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	_, err = conn.Write([]byte("this is some data"))
	time.Sleep(200 * time.Millisecond)
	// Close stream immediately
	conn.Close()
	assert.NoError(t, err)

	_, err = conn.Write([]byte("stop"))
	assert.Equal(t, ErrConnectionClosed, err)

	b := make([]byte, 4)
	n, err := conn.Read(b)
	assert.Equal(t, ErrConnectionClosed, err)
	assert.Equal(t, 0, n)

	// Now dial another connection on the same session to make sure that it works
	// even though the first session has a bunch of un-acked packets from the
	// server.
	conn, err = dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("abcd"))
	if !assert.NoError(t, err) {
		return
	}

	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Equal(t, 4, n) {
		return
	}
	assert.Equal(t, "abcd", string(b))
}

func TestPhysicalConnCloseLocalPrematurely(t *testing.T) {
	l, dialer, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	// Close physical connection immediately
	conn.(Stream).Session().(*session).Conn.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = conn.Write([]byte("stop"))
	assert.Equal(t, ErrBrokenPipe, err)

	b := make([]byte, 4)
	n, err := conn.Read(b)
	assert.Error(t, err)
	assert.Equal(t, 0, n)

	// Now dial again and make sure that works
	conn, err = dialer.Dial()
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
	l, dialer, _, err := echoServerAndDialerWithIdleInterval(uint16(max), 0, 50*time.Millisecond)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	var streams []net.Conn
	closeStreams := func() {
		for _, stream := range streams {
			stream.Close()
		}
	}
	defer closeStreams()

	_, connCount, err := fdcount.Matching("TCP")
	if !assert.NoError(t, err) {
		return
	}

	for i := 0; i <= max; i++ {
		stream, dialErr := dialer.Dial()
		if !assert.NoError(t, dialErr) {
			return
		}
		streams = append(streams, stream)
	}

	assert.NoError(t, connCount.AssertDelta(2), "Opening up to MaxID should have resulted in 1 connection (2 TCP sockets including server end)")

	stream, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	streams = append(streams, stream)

	assert.NoError(t, connCount.AssertDelta(4), "Opening past MaxID should have resulted in 2 connections (4 TCP sockets including server end)")

	// Sleep to make sure that a new session gets created
	time.Sleep(75 * time.Millisecond)

	stream, err = dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	streams = append(streams, stream)

	assert.NoError(t, connCount.AssertDelta(6), "Waiting past IdleInterval should have resulted in an additional connection for a total of 3 connections (6 TCP sockets including server end)")

	closeStreams()
	time.Sleep(ReadTimeout * 2)
	assert.NoError(t, connCount.AssertDelta(2), "Waiting for receive loops to finish after closing streams should have resulted in only one connection remaining open (2 TCP sockets including server end)")
}

func TestSessionPool(t *testing.T) {
	maxStreamsPerConn := 10
	maxLiveConns := 5
	redialSessionInterval := 10 * time.Millisecond
	l, d, _, err := echoServerAndDialer(uint16(maxStreamsPerConn))
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()
	bd := d.(*boundDialer)
	rd := bd.Dialer.(*dialer)
	rd.maxLiveConns = maxLiveConns
	rd.redialSessionInterval = redialSessionInterval
	oldDial := bd.dial
	var delay int64
	var dialed int64
	bd.dial = func() (net.Conn, error) {
		d := time.Duration(atomic.LoadInt64(&delay))
		time.Sleep(d)
		atomic.AddInt64(&dialed, 1)
		return oldDial()
	}
	dialNTimes := func(wg sync.WaitGroup, n int) {
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				conn, err := d.Dial()
				if !assert.NoError(t, err) {
					t.Fatal("Can't dial")
				}
				wg.Done()
				conn.Close()
			}()
		}
	}

	var wg sync.WaitGroup
	dialNTimes(wg, maxStreamsPerConn)
	wg.Wait()
	assert.EqualValues(t, 1, rd.getNumLivePending(), "Opening up to MaxID should have resulted in 1 session")

	atomic.StoreInt64(&delay, int64(10*redialSessionInterval))
	dialNTimes(wg, maxStreamsPerConn)
	time.Sleep(5 * redialSessionInterval)
	assert.EqualValues(t, maxLiveConns, rd.getNumLivePending(), "Should dial up to MaxLiveConns sessions when network becomes unusable")

	atomic.StoreInt64(&delay, 0)
	wg.Wait() // Make sure streams can be created after network recovers
	assert.EqualValues(t, maxLiveConns, rd.getNumLivePending(), "Should keep the live sessions when network recovers")

	time.Sleep(10 * redialSessionInterval)
	dialNTimes(wg, maxLiveConns-1) // drain all but one of the live sessions
	wg.Wait()
	time.Sleep(10 * redialSessionInterval)
	assert.EqualValues(t, minLiveConns, rd.getNumLivePending(), "Only one live session should be left after dialing a few")
	t.Logf("%v pyhsical connections in total were dialed", atomic.LoadInt64(&dialed))
}

func doTestConnBasicFlow(t *testing.T) {
	l, dialer, wg, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
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

func echoServerAndDialer(maxStreamsPerConn uint16) (net.Listener, BoundDialer, *sync.WaitGroup, error) {
	return echoServerAndDialerWithIdleInterval(maxStreamsPerConn, 0, 0)
}

func echoServerAndDialerWithIdleInterval(maxStreamsPerConn uint16, amplification int, idleInterval time.Duration) (net.Listener, BoundDialer, *sync.WaitGroup, error) {
	if amplification < 1 {
		amplification = 1
	}
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		return nil, nil, nil, err
	}

	wrapped, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, nil, err
	}

	pkFile, certFile := "pkfile.pem", "certfile.pem"
	wrapped, err = tlsdefaults.NewListener(wrapped, pkFile, certFile)
	if err != nil {
		return nil, nil, nil, err
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
					for i := 0; i < amplification; i++ {
						_, writeErr := conn.Write(b[:n])
						total += n
						if writeErr != nil {
							log.Errorf("Error writing for echo: %v", writeErr)
							return
						}
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
		IdleInterval:      idleInterval,
		PingInterval:      testPingInterval,
		Pool:              pool,
		Cipher:            AES128GCM,
		ServerPublicKey:   &pk.RSA().PublicKey})

	return l, dialer.BoundTo(doDial), &wg, nil
}

func TestCloseStreamAfterSessionClosed(t *testing.T) {
	l, dialer, _, err := echoServerAndDialer(0)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	conn, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	conn.(Stream).Session().Close()
	// Simply make sure it doesn't block
	conn.Close()
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
