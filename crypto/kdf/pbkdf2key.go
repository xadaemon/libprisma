package kdf

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/amazon-ion/ion-go/ion"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"reflect"
	"strings"
)

type Hash []byte
type Salt []byte

// NewSalt generates a random salt of the specified length and returns it as a Salt type. If an error occurs
// while generating the salt or the generated salt length does not match the specified length, a panic is raised
// with an error message.
func NewSalt(l int) Salt {
	salt := make([]byte, l)
	n, err := cryptorand.Read(salt)
	if n != l || err != nil {
		panic("Error getting salt!, check your OS")
	}
	return salt
}

// Pbkdf2Key represents a key derived using the PBKDF2 algorithm. It contains the following fields:
// - Hash: The derived key
// - Salt: The salt value used for key derivation
// - Algo: The algorithm used for key derivation
// - Iter: The number of iterations used for key derivation
// - KeyLen: The length of the derived key
// - HashType: The hash function used for key derivation
type Pbkdf2Key struct {
	Hash
	Salt
	Algo     string
	Iter     uint64
	KeyLen   uint64
	HashType string
}

var PbKdf2 = &Pbkdf2Key{}

func (d *Pbkdf2Key) Equals(other string) bool {
	otherKey := pbkdf2.Key([]byte(other), d.Salt, int(d.Iter), int(d.KeyLen), sha512.New)
	return subtle.ConstantTimeCompare(d.Hash, otherKey) == 1
}

func numToStr(i uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return base64.StdEncoding.EncodeToString(b)
}

func numFromString(s string) (uint64, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

func (d *Pbkdf2Key) String() string {
	saltEnc := base64.StdEncoding.EncodeToString(d.Salt)
	hashEnc := base64.StdEncoding.EncodeToString(d.Hash)
	iter := numToStr(d.Iter)
	keyLen := numToStr(d.KeyLen)
	return fmt.Sprintf("$%s;%s;%s;%s;%s;%s", d.Algo, d.HashType, iter, keyLen, saltEnc, hashEnc)
}

func (*Pbkdf2Key) FromString(s string) (Key, error) {
	if !strings.HasPrefix(s, "$") {
		return nil, errors.New("string is malformed")
	}

	parts := strings.Split(s, ";")
	if len(parts) != 6 {
		return nil, errors.New("too many or too little parts in encoded string")
	}

	algo := strings.TrimPrefix(parts[0], "$")
	if algo != "pbkdf2" {
		return nil, errors.New("algorithm does not match")
	}

	key, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	iter, oki := numFromString(parts[2])
	keyLen, okl := numFromString(parts[3])
	if !oki || !okl {
		return nil, errors.New("invalid iter or key-length found")
	}

	return &Pbkdf2Key{
		Hash:     key,
		Salt:     salt,
		Algo:     "pbkdf2",
		Iter:     iter,
		KeyLen:   keyLen,
		HashType: parts[1],
	}, nil
}

// Bytes returns the byte representation of the Pbkdf2Key object by marshaling
// it using the ion.MarshalBinary function. If an error occurs during the
// marshaling process, an empty byte slice is returned.
func (d *Pbkdf2Key) Bytes() []byte {
	b, _ := ion.MarshalBinary(d)
	return b
}

// FromBytes decodes a byte slice into a Pbkdf2Key object by unmarshaling it using the ion.Unmarshal function.
// If an error occurs during the unmarshaling process, nil and false are returned.
func (*Pbkdf2Key) FromBytes(b []byte) (Key, error) {
	var k = &Pbkdf2Key{}
	if err := ion.Unmarshal(b, k); err != nil {
		return nil, err
	}
	return k, nil
}

func (*Pbkdf2Key) Key(value string, iter int, keyLen int, h func() hash.Hash) Key {
	salt := NewSalt(8)
	hName := reflect.TypeOf(h())
	key := pbkdf2.Key([]byte(value), salt, iter, keyLen, h)
	return &Pbkdf2Key{
		Hash:     key,
		Salt:     salt,
		Algo:     "pbkdf2",
		Iter:     uint64(iter),
		KeyLen:   uint64(keyLen),
		HashType: hName.String(),
	}
}
