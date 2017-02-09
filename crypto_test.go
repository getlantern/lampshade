package lampshade

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/codahale/blake2"
	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/assert"
)

func TestInitAESCTR(t *testing.T) {
	doTestInit(t, AES128CTR)
}

func TestInitChaCha20(t *testing.T) {
	doTestInit(t, ChaCha20)
}

func doTestInit(t *testing.T, cipherCode Cipher) {
	privateKey, publicKey, secret, sendIV, recvIV, err := initCrypto(cipherCode)
	if !assert.NoError(t, err) {
		return
	}

	msg, err := buildClientInitMsg(publicKey, windowSize, maxPadding, cipherCode, secret, sendIV, recvIV)
	if !assert.NoError(t, err) {
		return
	}

	_windowSize, _maxPadding, _cipherCode, _secret, _sendIV, _recvIV, err := decodeClientInitMsg(privateKey, msg)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, windowSize, _windowSize)
	assert.Equal(t, maxPadding, _maxPadding)
	assert.Equal(t, cipherCode, _cipherCode)
	assert.EqualValues(t, secret, _secret)
	assert.EqualValues(t, sendIV, _sendIV)
	assert.EqualValues(t, recvIV, _recvIV)
}

func TestCryptoPrototypeAESCTR(t *testing.T) {
	doTestCryptoPrototype(t, AES128CTR)
}

func TestCryptoPrototypeChaCha20(t *testing.T) {
	doTestCryptoPrototype(t, AES128CTR)
}

func doTestCryptoPrototype(t *testing.T, cipherCode Cipher) {
	_, _, secret, sendIV, recvIV, err := initCrypto(cipherCode)
	if !assert.NoError(t, err) {
		return
	}

	clientEncrypt, err := newCipher(cipherCode, secret, sendIV)
	if !assert.NoError(t, err) {
		return
	}
	clientDecrypt, err := newCipher(cipherCode, secret, recvIV)
	if !assert.NoError(t, err) {
		return
	}
	serverEncrypt, err := newCipher(cipherCode, secret, recvIV)
	if !assert.NoError(t, err) {
		return
	}
	serverDecrypt, err := newCipher(cipherCode, secret, sendIV)
	if !assert.NoError(t, err) {
		return
	}

	// This scenario mimics and echo server
	for _, msg := range []string{"hi", "1", "", "and some more stuff"} {
		req := []byte(msg)
		reqEncrypted := make([]byte, len(req))
		resp := make([]byte, len(req))
		respEncrypted := make([]byte, len(req))
		respDecrypted := make([]byte, len(req))

		clientEncrypt.XORKeyStream(reqEncrypted, req)
		serverDecrypt.XORKeyStream(resp, reqEncrypted)
		serverEncrypt.XORKeyStream(respEncrypted, resp)
		clientDecrypt.XORKeyStream(respDecrypted, respEncrypted)
		assert.Equal(t, msg, string(respDecrypted))
	}
}

func initCrypto(cipherCode Cipher) (*rsa.PrivateKey, *rsa.PublicKey, []byte, []byte, []byte, error) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	secret, err := newSecret(cipherCode)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	sendIV, err := newIV(cipherCode)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	recvIV, err := newIV(cipherCode)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return pk.RSA(), &pk.RSA().PublicKey, secret, sendIV, recvIV, nil
}

func BenchmarkHMACMD5(b *testing.B) {
	secret := make([]byte, 16)
	rand.Read(secret)
	data := make([]byte, 8192)
	rand.Read(data)
	mac := hmac.New(md5.New, secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Write(data)
		mac.Sum(nil)
		mac.Reset()
	}
}

func BenchmarkHMACSHA256(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	data := make([]byte, 8192)
	rand.Read(data)
	mac := hmac.New(sha256.New, secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Write(data)
		mac.Sum(nil)
		mac.Reset()
	}
}

func BenchmarkHMACBlake2b512(b *testing.B) {
	secret := make([]byte, 64)
	rand.Read(secret)
	data := make([]byte, 8192)
	rand.Read(data)
	mac := hmac.New(blake2.NewBlake2B, secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Write(data)
		mac.Sum(nil)
		mac.Reset()
	}
}

func BenchmarkHMACBlake2b256(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	data := make([]byte, 8192)
	rand.Read(data)
	mac := blake2.New(&blake2.Config{
		Size: 32,
		Key:  secret,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Write(data)
		mac.Sum(nil)
		mac.Reset()
	}
}
