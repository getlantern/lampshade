package lampshade

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/require"
)

// TestAckForClosedStreamKeepsSessionInSync reproduces a session-frame parser
// desync: when the recvLoop encountered an ACK frame for an already-closed
// stream, it skipped the frame without consuming the 4-byte acked-frames
// field. The parser then misread the zero bytes of that field as a padding
// header and silently discarded every remaining frame coalesced in the same
// session frame, permanently stalling unrelated live streams.
//
// With AckOnFirst enabled (as the lantern http-proxy uses), the server sends
// an empty ACK for the first data frame of every inbound session frame, so a
// stream that writes and immediately closes reliably leaves a stale ACK in
// flight. This test churns such streams while victim streams echo large
// payloads; before the fix, a victim's echo frame would get discarded and its
// read would time out.
func TestAckForClosedStreamKeepsSessionInSync(t *testing.T) {
	pool := NewBufferPool(100 * 1024 * 1024)
	pk, err := keyman.GeneratePK(2048)
	require.NoError(t, err)

	wrapped, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	l := WrapListener(wrapped, pool, pk.RSA(), &ListenerOpts{
		AckOnFirst: true,
	})
	defer l.Close()

	go func() {
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			go io.Copy(conn, conn)
		}
	}()

	dialer := NewDialer(&DialerOpts{
		WindowSize:      50,
		MaxPadding:      32,
		Pool:            pool,
		Cipher:          AES128GCM,
		ServerPublicKey: &pk.RSA().PublicKey,
	})
	doDial := func() (net.Conn, error) {
		return net.Dial("tcp", l.Addr().String())
	}

	var stop int64
	stopped := func() bool { return atomic.LoadInt64(&stop) == 1 }
	defer atomic.StoreInt64(&stop, 1)

	// Churn streams: write one byte and close without reading the echo. The
	// server's ack-on-first ACK for such a stream always arrives after the
	// client has closed it, exercising the stale-ACK parsing path.
	var churnWG sync.WaitGroup
	const churners = 10
	churnWG.Add(churners)
	for i := 0; i < churners; i++ {
		go func() {
			defer churnWG.Done()
			for !stopped() {
				conn, dialErr := dialer.Dial(doDial)
				if dialErr != nil {
					return
				}
				conn.Write([]byte{1})
				conn.Close()
			}
		}()
	}

	// Victim streams: continuously echo full-size frames. If a stale ACK
	// desyncs the session-frame parser, one of these loses a frame and its
	// read times out.
	const victims = 10
	const rounds = 200
	errCh := make(chan error, victims)
	var victimWG sync.WaitGroup
	victimWG.Add(victims)
	for i := 0; i < victims; i++ {
		go func() {
			defer victimWG.Done()
			conn, dialErr := dialer.Dial(doDial)
			if dialErr != nil {
				errCh <- dialErr
				return
			}
			defer conn.Close()
			payload := make([]byte, MaxDataLen)
			echoed := make([]byte, MaxDataLen)
			for j := 0; j < rounds && !stopped(); j++ {
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				if _, writeErr := conn.Write(payload); writeErr != nil {
					errCh <- writeErr
					return
				}
				if _, readErr := io.ReadFull(conn, echoed); readErr != nil {
					errCh <- readErr
					return
				}
			}
			errCh <- nil
		}()
	}

	victimWG.Wait()
	atomic.StoreInt64(&stop, 1)
	churnWG.Wait()

	for i := 0; i < victims; i++ {
		require.NoError(t, <-errCh, "victim stream stalled: session-frame parser lost sync")
	}
}
