package lampshade

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/Yawning/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

var newSecret = _newSecret

// Cipher specifies a stream cipher
type Cipher byte

func (c Cipher) valid() bool {
	switch c {
	case AES128GCM, ChaCha20Poly1305, NoEncryption:
		return true
	default:
		return false
	}
}

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
	case AES128GCM, ChaCha20Poly1305:
		return 12
	default:
		return 1
	}
}

func (c Cipher) overhead() int {
	switch c {
	case AES128GCM, ChaCha20Poly1305:
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

// cryptoSpec encodes all the crypto configuration for a session.
type cryptoSpec struct {
	cipherCode Cipher
	secret     []byte
	metaSendIV []byte
	dataSendIV []byte
	metaRecvIV []byte
	dataRecvIV []byte
}

func newCryptoSpec(cipherCode Cipher) (*cryptoSpec, error) {
	cs := &cryptoSpec{
		cipherCode: cipherCode,
	}
	var err error
	cs.secret, err = newSecret()
	if err != nil {
		return nil, fmt.Errorf("Unable to create secret: %v", err)
	}
	cs.metaSendIV, err = newIV(metaIVSize)
	if err != nil {
		return nil, fmt.Errorf("Unable to create meta send initialization vector: %v", err)
	}
	cs.dataSendIV, err = newIV(cipherCode.ivSize())
	if err != nil {
		return nil, fmt.Errorf("Unable to create data send initialization vector: %v", err)
	}
	cs.metaRecvIV, err = newIV(metaIVSize)
	if err != nil {
		return nil, fmt.Errorf("Unable to create meta recv initialization vector: %v", err)
	}
	cs.dataRecvIV, err = newIV(cipherCode.ivSize())
	if err != nil {
		return nil, fmt.Errorf("Unable to create data recv initialization vector: %v", err)
	}

	return cs, nil
}

func (cs *cryptoSpec) reversed() *cryptoSpec {
	return &cryptoSpec{
		cipherCode: cs.cipherCode,
		secret:     cs.secret,
		metaSendIV: cs.metaRecvIV,
		dataSendIV: cs.dataRecvIV,
		metaRecvIV: cs.metaSendIV,
		dataRecvIV: cs.dataSendIV,
	}
}

func (cs *cryptoSpec) crypters() (metaEncrypt func([]byte), dataEncrypt func([]byte, []byte) []byte, metaDecrypt func([]byte), dataDecrypt func([]byte) ([]byte, error), err error) {
	metaEncrypt, err = newMetaEncrypter(cs.cipherCode, cs.secret, cs.metaSendIV)
	if err != nil {
		err = fmt.Errorf("Unable to build meta encrypter: %v", err)
		return
	}
	dataEncrypt, err = newEncrypter(cs.cipherCode, cs.secret, cs.dataSendIV)
	if err != nil {
		err = fmt.Errorf("Unable to build data encrypter: %v", err)
		return
	}
	metaDecrypt, err = newMetaDecrypter(cs.cipherCode, cs.secret, cs.metaRecvIV)
	if err != nil {
		err = fmt.Errorf("Unable to build meta decrypter: %v", err)
		return
	}
	dataDecrypt, err = newDecrypter(cs.cipherCode, cs.secret, cs.dataRecvIV)
	if err != nil {
		err = fmt.Errorf("Unable to build data decrypter: %v", err)
	}
	return
}

func _newSecret() ([]byte, error) {
	secret := make([]byte, maxSecretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random AES secret: %v", err)
	}

	return secret, nil
}

func newIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random initialization vector: %v", err)
	}

	return iv, nil
}

func newMetaEncrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte), error) {
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

func newMetaDecrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte), error) {
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

func cipherFor(cipherCode Cipher, secret []byte, iv []byte) (cipher.Stream, error) {
	switch cipherCode {
	case NoEncryption:
		log.Debug("WARNING - LENGTH ENCRYPTION DISABLED!!")
		return nil, nil
	default:
		// Unless encryption is disabled, always use ChaCha20 for encrypting length
		return chacha20.NewCipher(secret[:Cipher(ChaCha20Poly1305).secretSize()], iv)
	}
}

func newEncrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte, []byte) []byte, error) {
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

func newDecrypter(cipherCode Cipher, secret []byte, iv []byte) (func([]byte) ([]byte, error), error) {
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

func aeadFor(cipherCode Cipher, secret []byte) (cipher.AEAD, error) {
	// Use only as much of secret as we need for this cipher
	secret = secret[:cipherCode.secretSize()]
	switch cipherCode {
	case NoEncryption:
		log.Debug("WARNING - DATA ENCRYPTION DISABLED!!")
		return nil, nil
	case AES128GCM:
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate client AES cipher: %v", err)
		}
		return cipher.NewGCMWithNonceSize(block, cipherCode.ivSize())
	case ChaCha20Poly1305:
		return chacha20poly1305.New(secret)
	default:
		return nil, fmt.Errorf("Unknown cipher: %d", cipherCode)
	}
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

func buildClientInitMsg(serverPublicKey *rsa.PublicKey, windowSize int, maxPadding int, cs *cryptoSpec, ts time.Time) ([]byte, error) {
	var plainText []byte
	_windowSize := make([]byte, winSize)
	binaryEncoding.PutUint32(_windowSize, uint32(windowSize))
	plainText = append(plainText, _windowSize...)
	plainText = append(plainText, byte(maxPadding))
	plainText = append(plainText, byte(cs.cipherCode))
	plainText = append(plainText, cs.secret...)
	plainText = append(plainText, cs.metaSendIV...)
	plainText = append(plainText, cs.dataSendIV...)
	plainText = append(plainText, cs.metaRecvIV...)
	plainText = append(plainText, cs.dataRecvIV...)
	if !ts.IsZero() {
		_ts := make([]byte, tsSize)
		binaryEncoding.PutUint64(_ts, uint64(ts.Unix()))
		plainText = append(plainText, _ts...)
	}
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, plainText, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to encrypt init msg: %v", err)
	}
	return cipherText, nil
}

func decodeClientInitMsg(serverPrivateKey *rsa.PrivateKey, msg []byte) (windowSize int, maxPadding int, cs *cryptoSpec, ts time.Time, err error) {
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivateKey, msg, nil)
	if err != nil {
		return 0, 0, nil, time.Time{}, fmt.Errorf("Unable to decrypt init message: %v", err)
	}
	_windowSize, pt := consume(pt, winSize)
	windowSize = int(binaryEncoding.Uint32(_windowSize))
	_maxPadding, pt := consume(pt, 1)
	maxPadding = int(_maxPadding[0])
	_cipherCode, pt := consume(pt, 1)
	cs = &cryptoSpec{}
	cs.cipherCode = Cipher(_cipherCode[0])
	if !cs.cipherCode.valid() {
		return 0, 0, nil, time.Time{}, fmt.Errorf("Unknown cipher code: %d", cs.cipherCode)
	}
	ivSize := cs.cipherCode.ivSize()
	cs.secret, pt = consume(pt, maxSecretSize)
	cs.metaSendIV, pt = consume(pt, metaIVSize)
	cs.dataSendIV, pt = consume(pt, ivSize)
	cs.metaRecvIV, pt = consume(pt, metaIVSize)
	cs.dataRecvIV, pt = consume(pt, ivSize)
	if len(pt) >= tsSize {
		_ts, _ := consume(pt, tsSize)
		ts = time.Unix(int64(binaryEncoding.Uint64(_ts)), 0)
	}
	return
}

func consume(b []byte, length int) ([]byte, []byte) {
	return b[:length], b[length:]
}
