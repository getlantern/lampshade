package lampshade

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/Yawning/chacha20"
)

// Cipher specifies a stream cipher
type Cipher byte

func (c Cipher) secretSize() int {
	switch c {
	case AES128CTR:
		return 16
	case ChaCha20:
		return 32
	default:
		return 1
	}
}

func (c Cipher) ivSize() int {
	switch c {
	case AES128CTR:
		return 16
	case ChaCha20:
		return 12
	default:
		return 1
	}
}

func (c Cipher) String() string {
	switch c {
	case NoEncryption:
		return "None"
	case AES128CTR:
		return "AES128_CTR"
	case ChaCha20:
		return "ChaCha20"
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
	case AES128CTR:
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate client AES cipher: %v", err)
		}
		return cipher.NewCTR(block, iv), nil
	case ChaCha20:
		return chacha20.NewCipher(secret, iv)
	default:
		return nil, fmt.Errorf("Unknown cipher: %d", cipherCode)
	}
}

func buildClientInitMsg(serverPublicKey *rsa.PublicKey, windowSize int, maxPadding int, cipherCode Cipher, secret []byte, sendIV []byte, recvIV []byte) ([]byte, error) {
	secretSize := cipherCode.secretSize()
	ivSize := cipherCode.ivSize()
	plainText := make([]byte, 0, winSize+secretSize+ivSize*2)
	_windowSize := make([]byte, winSize)
	binaryEncoding.PutUint16(_windowSize, uint16(windowSize))
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
	windowSize = int(binaryEncoding.Uint16(_windowSize))
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
