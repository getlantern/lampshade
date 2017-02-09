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

func newSecret(cipherCode Cipher) ([]byte, error) {
	secret := make([]byte, secretSizes[cipherCode])
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random AES secret: %v", err)
	}

	return secret, nil
}

func newIV(cipherCode Cipher) ([]byte, error) {
	iv := make([]byte, ivSizes[cipherCode])
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random initialization vector: %v", err)
	}

	return iv, nil
}

func newCipher(cipherCode Cipher, secret []byte, iv []byte) (cipher.Stream, error) {
	switch cipherCode {
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
	secretSize := secretSizes[cipherCode]
	ivSize := ivSizes[cipherCode]
	plainText := make([]byte, 0, winSize+secretSize+ivSize*2)
	plainText = append(plainText, byte(windowSize))
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
	_windowSize, pt := consume(pt, 1)
	windowSize = int(_windowSize[0])
	_maxPadding, pt := consume(pt, 1)
	maxPadding = int(_maxPadding[0])
	_cipherCode, pt := consume(pt, 1)
	cipherCode = Cipher(_cipherCode[0])
	secretSize := secretSizes[cipherCode]
	ivSize := ivSizes[cipherCode]
	secret, pt = consume(pt, secretSize)
	sendIV, pt = consume(pt, ivSize)
	recvIV, _ = consume(pt, ivSize)
	return
}

func consume(b []byte, length int) ([]byte, []byte) {
	return b[:length], b[length:]
}
