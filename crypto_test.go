package lampshade

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/Yawning/chacha20"
	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkAlloc(b *testing.B) {
	source := make([]byte, 8192)
	rand.Read(source)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 8192)
		copy(buf, source)
	}
}

func BenchmarkNoAlloc(b *testing.B) {
	source := make([]byte, 8192)
	rand.Read(source)
	buf := make([]byte, 8192)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, source)
	}
}

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

func BenchmarkCipherAES128_CTR(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	data := make([]byte, 8192)
	rand.Read(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	encrypt := cipher.NewCTR(block, iv)
	decrypt := cipher.NewCTR(block, iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypt.XORKeyStream(data, data)
		decrypt.XORKeyStream(data, data)
	}
}

func BenchmarkCipherChaCha20(b *testing.B) {
	key := make([]byte, chacha20.KeySize)
	rand.Read(key)
	iv := make([]byte, chacha20.NonceSize)
	rand.Read(iv)
	data := make([]byte, 8192)
	buf := make([]byte, 8192)
	rand.Read(data)
	encrypt, err := chacha20.NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}
	decrypt, err := chacha20.NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypt.XORKeyStream(buf, data)
		decrypt.XORKeyStream(data, buf)
	}
}

func BenchmarkCipherAES128_GCM(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	data := make([]byte, 8192)
	out := make([]byte, 10240)
	rand.Read(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binaryEncoding.PutUint32(nonce, uint32(i))
		cipherText := aead.Seal(out[:0], nonce, data, nil)
		aead.Open(out[:0], nonce, cipherText, nil)
	}
}

func BenchmarkCipherChaCha20Poly1305(b *testing.B) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	iv := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(iv)
	data := make([]byte, 8192)
	out := make([]byte, 10240)
	rand.Read(data)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binaryEncoding.PutUint32(nonce, uint32(i))
		cipherText := aead.Seal(out[:0], nonce, data, nil)
		aead.Open(out[:0], nonce, cipherText, nil)
	}
}
