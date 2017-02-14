package lampshade

import (
	"crypto/rsa"
	"fmt"
	"io"
	"net"
)

type listener struct {
	wrapped          net.Listener
	pool             BufferPool
	serverPrivateKey *rsa.PrivateKey
	errCh            chan error
	connCh           chan net.Conn
}

// WrapListener wraps the given listener with support for multiplexing. Only
// connections that start with the special session start sequence will be
// multiplexed, otherwise connections behave as normal. This means that a single
// listener can be used to serve clients that do multiplexing as well as other
// clients that don't.
//
// Multiplexed sessions can only be initiated immediately after opening a
// connection to the Listener.
//
// wrapped - the net.Listener to wrap
//
// pool - BufferPool to use
//
// serverPrivateKey - if provided, this listener will expect connections to use
//                    encryption
func WrapListener(wrapped net.Listener, pool BufferPool, serverPrivateKey *rsa.PrivateKey) net.Listener {
	// TODO: add a maxWindowSize
	l := &listener{
		wrapped:          wrapped,
		pool:             pool,
		serverPrivateKey: serverPrivateKey,
		connCh:           make(chan net.Conn),
		errCh:            make(chan error),
	}
	go l.process()
	return l
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	}
}

func (l *listener) Addr() net.Addr {
	return l.wrapped.Addr()
}

func (l *listener) Close() error {
	go func() {
		l.errCh <- ErrListenerClosed
	}()
	// Closing wrapped has the side effect of making the process loop terminate
	// because it will fail to accept from wrapped.
	return l.wrapped.Close()
}

func (l *listener) process() {
	for {
		conn, err := l.wrapped.Accept()
		if err != nil {
			l.errCh <- &netError{err.Error(), false, false}
			return
		}
		go l.onConn(conn)
	}
}

func (l *listener) onConn(conn net.Conn) {
	err := l.doOnConn(conn)
	if err != nil {
		l.errCh <- &netError{err.Error(), false, true}
		conn.Close()
	}
}

func (l *listener) doOnConn(conn net.Conn) error {
	// Read client init msg
	initMsg := make([]byte, clientInitSize)
	// Try to read start sequence
	_, err := io.ReadFull(conn, initMsg)
	if err != nil {
		return fmt.Errorf("Unable to read client init msg: %v", err)
	}
	windowSize, maxPadding, cipherCode, secret, sendIV, recvIV, err := decodeClientInitMsg(l.serverPrivateKey, initMsg)
	if err != nil {
		return fmt.Errorf("Unable to decode client init msg: %v", err)
	}
	decrypt, err := newDecrypter(cipherCode, secret, sendIV)
	if err != nil {
		return fmt.Errorf("Unable to initialize decryption cipher: %v", err)
	}
	encrypt, err := newEncrypter(cipherCode, secret, recvIV)
	if err != nil {
		return fmt.Errorf("Unable to initialize encryption cipher: %v", err)
	}
	startSession(conn, windowSize, maxPadding, decrypt, encrypt, nil, l.pool, l.connCh, nil)
	return nil
}
