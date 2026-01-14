package symmetrical

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
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
	var outBuf bytes.Buffer
	outBuf.Grow(len(data) + aes.BlockSize)
	if len(data) < aes.BlockSize {
		cryptography.ANSIPad(data, aes.BlockSize, uint8(len(data)), true)
	}
	blocker := cryptography.NewBlocker(aes.BlockSize, data)
	encrypted := make([]byte, aes.BlockSize)
	for {
		n, block := blocker.Next()
		if n == 0 {
			break
		}
		s.enc.CryptBlocks(encrypted, block)
		s.h.Write(block)
		outBuf.Write(encrypted)
	}
	return outBuf.Bytes(), nil
}

func (s *SecureAES) Decrypt(data []byte) ([]byte, error) {
	var decryptedBuffer bytes.Buffer
	decrypted := make([]byte, aes.BlockSize)
	cypertextBuffer := bytes.NewBuffer(data)
	block := make([]byte, aes.BlockSize)
	for {
		n, _ := cypertextBuffer.Read(block)
		if n == 0 {
			break
		}
		s.dec.CryptBlocks(decrypted, block)
		s.h.Write(decrypted)
		decryptedBuffer.Write(decrypted)
	}
	return decryptedBuffer.Bytes(), nil
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

// EncryptToBytes encrypts the data, and returns [C, IV, Tag] where
//
// C is the cyphertext, IV is the init vector. C is [len,data]
func (s *SecureAES) EncryptToBytes(data []byte) ([]byte, error) {
	iv := s.GetIV()
	dataLen := uint64(len(data))
	var toEncryptBuffer bytes.Buffer
	toEncryptBuffer.Grow(int(dataLen) + 8)
	binary.Write(&toEncryptBuffer, binary.LittleEndian, dataLen)
	toEncryptBuffer.Write(data)
	toEncryptBuffer.Bytes()
	encrypted, err := s.Encrypt(toEncryptBuffer.Bytes())
	if err != nil {
		return nil, err
	}
	tag := s.GetTag()
	encrypted = append(encrypted, iv...)
	encrypted = append(encrypted, tag...)

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

	dataLen := binary.LittleEndian.Uint64(decrypted[:8])

	return decrypted[8 : 8+dataLen], nil
}
