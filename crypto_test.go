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

func TestXOR(t *testing.T) {
	iv := make([]byte, 12)
	_, err := rand.Read(iv)
	if !assert.NoError(t, err) {
		return
	}
	t.Log(iv)

	seq := make([]byte, 12)
	binaryEncoding.PutUint64(seq[4:], 5)
	t.Log(seq)

	fastXORBytes(seq, seq, iv)
	t.Log(seq)
}

func TestInitAESGCM(t *testing.T) {
	doTestInit(t, AES128GCM)
}

func TestInitChaCha20Poly1305(t *testing.T) {
	doTestInit(t, ChaCha20Poly1305)
}

func doTestInit(t *testing.T, cipherCode Cipher) {
	privateKey, publicKey, cs, err := initCrypto(cipherCode)
	if !assert.NoError(t, err) {
		return
	}

	msg, err := buildClientInitMsg(publicKey, windowSize, maxPadding, cs)
	if !assert.NoError(t, err) {
		return
	}

	_windowSize, _maxPadding, _cs, err := decodeClientInitMsg(privateKey, msg)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, windowSize, _windowSize)
	assert.Equal(t, maxPadding, _maxPadding)
	assert.Equal(t, cs.cipherCode, _cs.cipherCode)
	assert.EqualValues(t, cs.secret, _cs.secret)
	assert.EqualValues(t, cs.metaSendIV, _cs.metaSendIV)
	assert.EqualValues(t, cs.dataSendIV, _cs.dataSendIV)
	assert.EqualValues(t, cs.metaRecvIV, _cs.metaRecvIV)
	assert.EqualValues(t, cs.dataRecvIV, _cs.dataRecvIV)
}

func TestCryptoPrototypeNoEncryption(t *testing.T) {
	doTestCryptoPrototype(t, NoEncryption)
}

func TestCryptoPrototypeAESCTR(t *testing.T) {
	doTestCryptoPrototype(t, AES128GCM)
}

func TestCryptoPrototypeChaCha20(t *testing.T) {
	doTestCryptoPrototype(t, ChaCha20Poly1305)
}

func doTestCryptoPrototype(t *testing.T, cipherCode Cipher) {
	_, _, cs, err := initCrypto(cipherCode)
	if !assert.NoError(t, err) {
		return
	}

	_, clientEncrypt, _, clientDecrypt, err := cs.crypters()
	if !assert.NoError(t, err) {
		return
	}
	_, serverEncrypt, _, serverDecrypt, err := cs.reversed().crypters()
	if !assert.NoError(t, err) {
		return
	}

	overhead := cipherCode.overhead()

	// This scenario mimics and echo server
	for _, msg := range []string{"hi", "1", "", "and some more stuff"} {
		req := []byte(msg)
		b := make([]byte, len(req))

		b = clientEncrypt(b, req)
		assert.Equal(t, len(req)+overhead, len(b), msg)
		b, err = serverDecrypt(b)
		if !assert.NoError(t, err, msg) {
			continue
		}
		assert.Equal(t, len(req), len(b), msg)
		b = serverEncrypt(b, b)
		assert.Equal(t, len(req)+overhead, len(b), msg)
		b, err = clientDecrypt(b)
		if !assert.NoError(t, err, msg) {
			continue
		}
		assert.Equal(t, msg, string(b))
	}
}

func initCrypto(cipherCode Cipher) (*rsa.PrivateKey, *rsa.PublicKey, *cryptoSpec, error) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		return nil, nil, nil, err
	}

	cs, err := newCryptoSpec(cipherCode)
	return pk.RSA(), &pk.RSA().PublicKey, cs, err
}

func BenchmarkCipherAES128_CTR(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	data := make([]byte, MaxDataLen)
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
	data := make([]byte, MaxDataLen)
	buf := make([]byte, MaxDataLen)
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
	data := make([]byte, MaxDataLen)
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
	data := make([]byte, MaxDataLen)
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
