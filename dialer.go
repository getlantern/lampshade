package lampshade

import (
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
)

// Dialer is like StreamDialer but provides a function that returns a net.Conn
// for easier integration with code that needs this interface.
func Dialer(windowSize int, maxPadding int, maxStreamsPerConn uint16, pool BufferPool, cipherCode Cipher, serverPublicKey *rsa.PublicKey, dial func() (net.Conn, error)) func() (net.Conn, error) {
	d := StreamDialer(windowSize, maxPadding, maxStreamsPerConn, pool, cipherCode, serverPublicKey, dial)
	return func() (net.Conn, error) {
		return d()
	}
}

// StreamDialer wraps the given dial function with support for multiplexing. The
// returned Streams look and act just like regular net.Conns. The Dialer
// will multiplex everything over a single net.Conn until it encounters a read
// or write error on that Conn. At that point, it will dial a new conn for
// future streams, until there's a problem with that Conn, and so on and so
// forth.
//
// If a new physical connection is needed but can't be established, the dialer
// returns the underlying dial error.
//
// windowSize - how many frames to queue, used to bound memory use. Each frame
// takes about 8KB of memory. If <= 0, defaults to 50.
//
// maxPadding - maximum random padding to use when necessary.
//
// maxStreamsPerConn - limits the number of streams per physical connection. If
//                     <=0, defaults to max uint16.
//
// pool - BufferPool to use
//
// cipherCode - which cipher to use, 1 = AES128 in CTR mode, 2 = ChaCha20
//
// serverPublicKey - if provided, this dialer will use encryption.
//
// dial - function to open an underlying connection.
func StreamDialer(windowSize int, maxPadding int, maxStreamsPerConn uint16, pool BufferPool, cipherCode Cipher, serverPublicKey *rsa.PublicKey, dial func() (net.Conn, error)) func() (Stream, error) {
	if windowSize <= 0 {
		windowSize = defaultWindowSize
	}
	if maxStreamsPerConn <= 0 || maxStreamsPerConn > maxID {
		maxStreamsPerConn = maxID
	}
	d := &dialer{
		doDial:           dial,
		windowSize:       windowSize,
		maxPadding:       maxPadding,
		maxStreamPerConn: maxStreamsPerConn,
		pool:             pool,
		cipherCode:       cipherCode,
		serverPublicKey:  serverPublicKey,
	}
	return d.dial
}

type dialer struct {
	doDial           func() (net.Conn, error)
	windowSize       int
	maxPadding       int
	maxStreamPerConn uint16
	pool             BufferPool
	cipherCode       Cipher
	serverPublicKey  *rsa.PublicKey
	current          *session
	id               uint16
	mx               sync.Mutex
}

func (d *dialer) dial() (Stream, error) {
	d.mx.Lock()
	current := d.current
	idsExhausted := false
	if d.id > d.maxStreamPerConn {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		idsExhausted = true
		d.id = 0
	}

	// TODO: support pooling of connections (i.e. keep multiple physical connections in flight)
	if current == nil || idsExhausted {
		var err error
		current, err = d.startSession()
		if err != nil {
			return nil, err
		}
	}
	id := d.id
	d.id++
	d.mx.Unlock()

	c, _ := current.getOrCreateStream(id)
	return c, nil
}

func (d *dialer) startSession() (*session, error) {
	conn, err := d.doDial()
	if err != nil {
		d.mx.Unlock()
		return nil, err
	}

	// Each session gets a new secret
	secret, err := newSecret(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES secret: %v", err)
	}

	// Create initialization vector for sending to server
	sendIV, err := newIV(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create send initialization vector: %v", err)
	}

	// Create initialization vector for receiving from server
	recvIV, err := newIV(d.cipherCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to create recv initialization vector: %v", err)
	}

	// Generate the client init message
	clientInitMsg, err := buildClientInitMsg(d.serverPublicKey, d.windowSize, d.maxPadding, d.cipherCode, secret, sendIV, recvIV)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate client init message: %v", err)
	}

	decrypt, err := newCipher(d.cipherCode, secret, recvIV)
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize decryption cipher: %v", err)
	}
	encrypt, err := newCipher(d.cipherCode, secret, sendIV)
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize encryption cipher: %v", err)
	}

	d.current = startSession(conn, d.windowSize, d.maxPadding, decrypt, encrypt, clientInitMsg, d.pool, nil, d.sessionClosed)
	return d.current, nil
}

func (d *dialer) sessionClosed(s *session) {
	d.mx.Lock()
	if d.current == s {
		log.Debug("Current session no longer usable, clearing")
		d.current = nil
	}
	d.mx.Unlock()
}
