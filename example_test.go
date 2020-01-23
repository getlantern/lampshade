package lampshade

import (
	"github.com/getlantern/keyman"

	"crypto/rsa"
	"net"
)

func ExampleNewDialer() {
	publicKey := loadPublicKey()

	dialer := NewDialer(&DialerOpts{
		Pool:            NewBufferPool(100),
		Cipher:          AES128GCM,
		ServerPublicKey: &publicKey,
	}).BoundTo(func() (net.Conn, error) {
		return net.Dial("tcp", "myserver:9352")
	})

	// Get a connection to the server
	dialer.Dial()
}

func ExampleWrapListener() {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		return
	}

	l, err := net.Listen("tcp", ":9352")
	if err != nil {
		return
	}

	ll := WrapListener(l, NewBufferPool(100), pk.RSA(), &ListenerOpts{
		AckOnFirst: true,
	})
	for {
		conn, err := ll.Accept()
		if err != nil {
			// handle error
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	// empty, just used for example
}

func loadPublicKey() rsa.PublicKey {
	// content doesn't matter, just used for example
	return rsa.PublicKey{}
}
