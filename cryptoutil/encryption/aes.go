package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"github.com/stateprism/libprisma/cryptoutil"
	"hash"
)

type EncryptionError int

const (
	ErrInvalidKeyLength EncryptionError = iota
)

func (e EncryptionError) Error() string {
	switch e {
	case ErrInvalidKeyLength:
		return "invalid key length"
	default:
		return "unknown error"
	}
}

type SecureAES struct {
	iv   []byte
	key  []byte
	iAes cipher.Block
	enc  cipher.BlockMode
	dec  cipher.BlockMode
	h    hash.Hash
}

func NewSecureAES(key []byte) (*SecureAES, error) {
	key = cryptoutil.SeededRandomData(key, 32)
	iv := cryptoutil.NewRandom(aes.BlockSize)
	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(bc, iv)
	dec := cipher.NewCBCDecrypter(bc, iv)
	h := sha256.New()
	s := &SecureAES{
		iv:   iv,
		key:  key,
		iAes: bc,
		enc:  enc,
		dec:  dec,
		h:    h,
	}
	// Reset the hash state to known state
	s.Reset()

	return s, nil
}

func NewSecureAESWithSafeKey(key []byte) (*SecureAES, error) {
	iv := cryptoutil.NewRandom(aes.BlockSize)
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(bc, iv)
	dec := cipher.NewCBCDecrypter(bc, iv)
	h := sha256.New()
	s := &SecureAES{
		iv:   iv,
		key:  key,
		iAes: bc,
		enc:  enc,
		dec:  dec,
		h:    h,
	}
	// Reset the hash state to known state
	s.Reset()

	return s, nil
}

func (s *SecureAES) GetKey() []byte {
	return s.key
}

func (s *SecureAES) GetIV() []byte {
	return s.iv
}

func (s *SecureAES) SetIV(iv []byte) bool {
	if len(iv) != aes.BlockSize {
		return false
	}
	s.iv = iv
	s.enc = cipher.NewCBCEncrypter(s.iAes, iv)
	s.dec = cipher.NewCBCDecrypter(s.iAes, iv)
	return true
}

func (s *SecureAES) Encrypt(data []byte) ([]byte, error) {
	out := make([]byte, len(data)+len(data)%aes.BlockSize)
	outBlocker := cryptoutil.NewBlocker(aes.BlockSize, out)
	blocker := cryptoutil.NewBlocker(aes.BlockSize, data)
	for {
		_, encrypted := outBlocker.Next()
		n, block := blocker.Next()
		if n == 0 {
			break
		}
		if n < aes.BlockSize {
			block, _ = cryptoutil.Pad(block, aes.BlockSize)
		}
		s.enc.CryptBlocks(encrypted, block)
		s.h.Write(block)
	}
	return out, nil
}

func (s *SecureAES) Decrypt(data []byte, tag []byte) ([]byte, error) {
	if len(tag) != s.GetTagSize() {
		return nil, errors.New("tag size mismatch")
	}
	// Reset the tag calculation
	s.Reset()
	decrypted := make([]byte, len(data))
	decryptedBlocker := cryptoutil.NewBlocker(aes.BlockSize, decrypted)
	blocker := cryptoutil.NewBlocker(aes.BlockSize, data)
	for {
		_, decrypted := decryptedBlocker.Next()
		n, block := blocker.Next()
		if n == 0 {
			break
		}
		s.dec.CryptBlocks(decrypted, block)
		s.h.Write(decrypted)
	}
	decrypted, err := cryptoutil.Unpad(decrypted, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	calculatedTag := s.GetTag()
	if !cryptoutil.SecureCompare(tag, calculatedTag) {
		return nil, errors.New("tag mismatch")
	}
	return decrypted, nil
}

// GetTag returns the tag for the all the encryption that was performed up to the call to GetTag
func (s *SecureAES) GetTag() []byte {
	var tag []byte
	tag = s.h.Sum(tag)
	return tag
}

func (s *SecureAES) GetTagSize() int {
	return s.h.Size()
}

func (s *SecureAES) GetIvSize() int {
	return s.iAes.BlockSize()
}

func (s *SecureAES) TagPlusIVSize() int {
	return s.iAes.BlockSize() + s.h.Size()
}

// Reset resets the encryption state, with a new hash state for the tag
func (s *SecureAES) Reset() {
	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(s.iv)
}

// FullReset resets the encryption state, with a new hash state for the tag and a new IV
func (s *SecureAES) FullReset() {
	s.iv = cryptoutil.NewRandom(aes.BlockSize)
	s.enc = cipher.NewCBCEncrypter(s.iAes, s.iv)
	s.dec = cipher.NewCBCDecrypter(s.iAes, s.iv)
	s.Reset()
}

func (s *SecureAES) Dispose() {
	// overwrite the key and iv with random data
	s.iv = cryptoutil.NewRandom(aes.BlockSize)
	s.key = cryptoutil.NewRandom(32)
	s.iAes = nil
	s.enc = nil
	s.dec = nil
	s.Reset()
}

// EncryptToBytes encrypts the data and returns the encrypted data with the IV and tag appended
// it returns [data, IV, tag]
func (s *SecureAES) EncryptToBytes(data []byte) ([]byte, error) {
	encrypted, err := s.Encrypt(data)
	if err != nil {
		return nil, err
	}
	encrypted = append(encrypted, s.GetIV()...)
	encrypted = append(encrypted, s.GetTag()...)
	return encrypted, nil
}

// DecryptFromBytes decrypts the data and returns the decrypted data, it expects the data to be in the order [data, IV, tag]
func (s *SecureAES) DecryptFromBytes(data []byte) ([]byte, error) {
	iv := make([]byte, s.GetIvSize())
	tag := make([]byte, s.GetTagSize())
	tagIv := data[len(data)-s.TagPlusIVSize():]
	encrypted := data[:len(data)-s.TagPlusIVSize()]
	copy(iv, tagIv[:s.GetIvSize()])
	copy(tag, tagIv[s.GetIvSize():])
	s.SetIV(iv)

	decrypted, err := s.Decrypt(encrypted, tag)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}