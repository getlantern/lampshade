package lampshade

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/Yawning/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher specifies a stream cipher
type Cipher byte

func (c Cipher) secretSize() int {
	switch c {
	case AES128GCM:
		return 16
	case ChaCha20Poly1305:
		return 32
	default:
		return 1
	}
}

func (c Cipher) ivSize() int {
	switch c {
	case AES128GCM:
		return 16
	case ChaCha20Poly1305:
		return 12
	default:
		return 1
	}
}

func (c Cipher) overhead() int {
	switch c {
	case AES128GCM:
		return 16
	case ChaCha20Poly1305:
		return 16
	default:
		return 0
	}
}

func (c Cipher) String() string {
	switch c {
	case NoEncryption:
		return "None"
	case AES128GCM:
		return "AES128_GCM"
	case ChaCha20Poly1305:
		return "ChaCha20_Poly1305"
	default:
		return "unknown"
	}
}

func newSecret(cipherCode Cipher) ([]byte, error) {
	secret := make([]byte, cipherCode.secretSize())
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random AES secret: %v", err)
	}

	return secret, nil
}

func newIV(cipherCode Cipher) ([]byte, error) {
	iv := make([]byte, cipherCode.ivSize())
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random initialization vector: %v", err)
	}

	return iv, nil
}

func newDecrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte), error) {
	c, err := cipherFor(cipherCode, secret, iv)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return func(b []byte) {
		}, nil
	}
	return func(b []byte) {
		c.XORKeyStream(b, b)
	}, nil
}

func newEncrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte, []byte), error) {
	c, err := cipherFor(cipherCode, secret, iv)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return func(dst []byte, src []byte) {
			copy(dst, src)
		}, nil
	}
	return func(dst []byte, src []byte) {
		c.XORKeyStream(dst, src)
	}, nil
}

func cipherFor(cipherCode Cipher, secret []byte, iv []byte) (cipher.Stream, error) {
	switch cipherCode {
	case NoEncryption:
		log.Debug("WARNING - ENCRYPTION DISABLED!!")
		return nil, nil
	case AES128GCM:
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate client AES cipher: %v", err)
		}
		return cipher.NewCTR(block, iv), nil
	case ChaCha20Poly1305:
		return chacha20.NewCipher(secret, iv)
	default:
		return nil, fmt.Errorf("Unknown cipher: %d", cipherCode)
	}
}

func newDecrypter2(cipherCode Cipher, secret []byte, iv []byte) (func([]byte) ([]byte, error), error) {
	aead, err := aeadFor(cipherCode, secret)
	if err != nil {
		return nil, err
	}
	if aead == nil {
		return func(b []byte) ([]byte, error) {
			return b, nil
		}, nil
	}
	nonce := nonceGenerator(iv)
	return func(b []byte) ([]byte, error) {
		return aead.Open(b[:0], nonce(), b, nil)
	}, nil
}

func newEncrypter2(cipherCode Cipher, secret []byte, iv []byte) (func([]byte, []byte) []byte, error) {
	aead, err := aeadFor(cipherCode, secret)
	if err != nil {
		return nil, err
	}
	if aead == nil {
		return func(dst []byte, src []byte) []byte {
			copy(dst, src)
			return dst
		}, nil
	}
	nonce := nonceGenerator(iv)
	return func(dst []byte, src []byte) []byte {
		return aead.Seal(dst[:0], nonce(), src, nil)
	}, nil
}

// nonceGenerator creates a function that derives a nonce by XOR'ing an IV and
// a counter, as done by TLS 1.3. See https://blog.cloudflare.com/tls-nonce-nse/
func nonceGenerator(iv []byte) func() []byte {
	ns := len(iv)
	ctr := uint64(0)
	ctrBytes := make([]byte, ns)
	ctrSlice := ctrBytes[ns-8:]
	nonce := make([]byte, ns)
	return func() []byte {
		binaryEncoding.PutUint64(ctrSlice, ctr)
		xorBytes(nonce, iv, ctrBytes)
		ctr++
		return nonce
	}
}

func aeadFor(cipherCode Cipher, secret []byte) (cipher.AEAD, error) {
	switch cipherCode {
	case NoEncryption:
		log.Debug("WARNING - ENCRYPTION DISABLED!!")
		return nil, nil
	case AES128GCM:
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate client AES cipher: %v", err)
		}
		return cipher.NewGCMWithNonceSize(block, 16)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(secret)
	default:
		return nil, fmt.Errorf("Unknown cipher: %d", cipherCode)
	}
}

func buildClientInitMsg(serverPublicKey *rsa.PublicKey, windowSize int, maxPadding int, cipherCode Cipher, secret []byte, sendIV []byte, recvIV []byte) ([]byte, error) {
	secretSize := cipherCode.secretSize()
	ivSize := cipherCode.ivSize()
	plainText := make([]byte, 0, winSize+secretSize+ivSize*2)
	_windowSize := make([]byte, winSize)
	binaryEncoding.PutUint32(_windowSize, uint32(windowSize))
	plainText = append(plainText, _windowSize...)
	plainText = append(plainText, byte(maxPadding))
	plainText = append(plainText, byte(cipherCode))
	plainText = append(plainText, secret...)
	plainText = append(plainText, sendIV...)
	plainText = append(plainText, recvIV...)
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, plainText, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to encrypt init msg: %v", err)
	}
	return cipherText, nil
}

func decodeClientInitMsg(serverPrivateKey *rsa.PrivateKey, msg []byte) (windowSize int, maxPadding int, cipherCode Cipher, secret []byte, sendIV []byte, recvIV []byte, err error) {
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivateKey, msg, nil)
	if err != nil {
		return 0, 0, 0, nil, nil, nil, fmt.Errorf("Unable to decrypt init message: %v", err)
	}
	_windowSize, pt := consume(pt, winSize)
	windowSize = int(binaryEncoding.Uint32(_windowSize))
	_maxPadding, pt := consume(pt, 1)
	maxPadding = int(_maxPadding[0])
	_cipherCode, pt := consume(pt, 1)
	cipherCode = Cipher(_cipherCode[0])
	secretSize := cipherCode.secretSize()
	ivSize := cipherCode.ivSize()
	secret, pt = consume(pt, secretSize)
	sendIV, pt = consume(pt, ivSize)
	recvIV, _ = consume(pt, ivSize)
	return
}

func consume(b []byte, length int) ([]byte, []byte) {
	return b[:length], b[length:]
}
