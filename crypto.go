package lampshade

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func newAESSecret() ([]byte, error) {
	secret := make([]byte, secretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random AES secret: %v", err)
	}

	return secret, nil
}

func newIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random initialization vector: %v", err)
	}

	return iv, nil
}

func newAESCipher(secret []byte, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate client AES cipher: %v", err)
	}
	return cipher.NewCTR(block, iv), nil
}

func buildClientInitMsg(serverPublicKey *rsa.PublicKey, windowSize int, maxPadding int, secret []byte, sendIV []byte, recvIV []byte) ([]byte, error) {
	plainText := make([]byte, 0, winSize+secretSize+ivSize*2)
	plainText = append(plainText, byte(windowSize))
	plainText = append(plainText, byte(maxPadding))
	plainText = append(plainText, secret...)
	plainText = append(plainText, sendIV...)
	plainText = append(plainText, recvIV...)
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, plainText, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to encrypt init msg: %v", err)
	}
	return cipherText, nil
}

func decodeClientInitMsg(serverPrivateKey *rsa.PrivateKey, msg []byte) (windowSize int, maxPadding int, secret []byte, sendIV []byte, recvIV []byte, err error) {
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivateKey, msg, nil)
	if err != nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("Unable to decrypt init message: %v", err)
	}
	_windowSize, pt := consume(pt, 1)
	windowSize = int(_windowSize[0])
	_maxPadding, pt := consume(pt, 1)
	maxPadding = int(_maxPadding[0])
	secret, pt = consume(pt, secretSize)
	sendIV, pt = consume(pt, ivSize)
	recvIV, _ = consume(pt, ivSize)
	return
}

func consume(b []byte, length int) ([]byte, []byte) {
	return b[:length], b[length:]
}
