package symmetrical

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/xadaemon/libprisma/cryptography"
	"golang.org/x/crypto/pbkdf2"
)

type AESSize int

const (
	AES128 AESSize = 16
	AES192 AESSize = 24
	AES256 AESSize = 32
)

type SecureAES struct {
	iv   []byte
	key  []byte
	iAes cipher.Block
	enc  cipher.BlockMode
	dec  cipher.BlockMode
	h    hash.Hash
}

// NewSecureAES creates a new SecureAES object with the given key
// The key will be used to seed a chacha8 CSPRNG to generate a salt for the key derivation function,
// in this case, PBKDF2 with 4096 iterations and a key length of corresponding to aesSize
// the original key is not stored in the SecureAES struct only the derived bytes
func NewSecureAES(key []byte, aesSize AESSize) (SecureCypher, error) {
	keyDerivedSalt := cryptography.SeededRandomData(key, 64)
	key = pbkdf2.Key(key, keyDerivedSalt, 4096, int(aesSize), sha256.New)
	iv := cryptography.SeededRandomData(pbkdf2.Key(key, keyDerivedSalt, 4096, int(aesSize), sha256.New), aes.BlockSize)
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

func (s *SecureAES) GetBlockSize() int {
	return aes.BlockSize
}

func (s *SecureAES) GetKey() []byte {
	return s.key
}

func (s *SecureAES) GetIV() []byte {
	return s.iv
}

func (s *SecureAES) SetIV(iv []byte) {
	if len(iv) != aes.BlockSize {
		panic("invalid IV size")
	}
	s.iv = iv
	s.enc = cipher.NewCBCEncrypter(s.iAes, iv)
	s.dec = cipher.NewCBCDecrypter(s.iAes, iv)
}

func (s *SecureAES) Encrypt(data []byte) ([]byte, error) {
	var out []byte
	if len(data) > aes.BlockSize {
		out = make([]byte, FindNextDiv(len(data), aes.BlockSize))
	} else {
		out = make([]byte, aes.BlockSize)
	}
	outBlocker := cryptography.NewBlocker(aes.BlockSize, out)
	blocker := cryptography.NewBlocker(aes.BlockSize, data)
	for {
		_, encrypted := outBlocker.Next()
		n, block := blocker.Next()
		if n == 0 {
			break
		}
		if n < aes.BlockSize {
			block, _ = cryptography.Pad(block, aes.BlockSize)
		}
		s.enc.CryptBlocks(encrypted, block)
		s.h.Write(block)
	}
	return out, nil
}

func (s *SecureAES) Decrypt(data []byte) ([]byte, error) {
	decrypted := make([]byte, len(data))
	decryptedBlocker := cryptography.NewBlocker(aes.BlockSize, decrypted)
	blocker := cryptography.NewBlocker(aes.BlockSize, data)
	for {
		_, decrypted := decryptedBlocker.Next()
		n, block := blocker.Next()
		if n == 0 {
			break
		}
		s.dec.CryptBlocks(decrypted, block)
		s.h.Write(decrypted)
	}
	decrypted, err := cryptography.Unpad(decrypted, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// GetTag returns the tag for the all the encryption that was performed up to the call to GetTag
func (s *SecureAES) GetTag() []byte {
	var tag []byte
	tag = s.h.Sum(tag)
	return tag
}

// GetKeyThumbprint returns the thumbprint of the key currently loaded in the SecureAES object as a SHA-512 hash
func (s *SecureAES) GetKeyThumbprint() []byte {
	h := sha512.New()
	h.Write(s.key)
	return h.Sum(nil)
}

// CheckKeyThumbprint checks if the given thumbprint matches the thumbprint of the key currently loaded in the SecureAES object
func (s *SecureAES) CheckKeyThumbprint(thumbprint []byte) bool {
	return cryptography.SecureCompare(thumbprint, s.GetKeyThumbprint())
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
	s.iv = cryptography.NewRandom(aes.BlockSize)
	s.enc = cipher.NewCBCEncrypter(s.iAes, s.iv)
	s.dec = cipher.NewCBCDecrypter(s.iAes, s.iv)
	s.Reset()
}

func (s *SecureAES) Dispose() {
	// overwrite the key and iv with random data
	s.iv = cryptography.NewRandom(aes.BlockSize)
	s.key = cryptography.NewRandom(32)
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
	s.Reset()

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	if !cryptography.SecureCompare(tag, s.GetTag()) {
		return nil, ErrTagMismatch
	}

	return decrypted, nil
}
