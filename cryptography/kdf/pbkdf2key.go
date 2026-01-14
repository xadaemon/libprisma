package kdf

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"

	"github.com/xadaemon/libprisma/cryptography"
	"golang.org/x/crypto/pbkdf2"
)

type Hash []byte
type Salt []byte

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

var PbKdf2 = Pbkdf2Key{}

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

func (Pbkdf2Key) KeyFromStr(value string, iter int, keyLen int, h func() hash.Hash) Key {
	return PbKdf2.Key([]byte(value), iter, keyLen, h)
}

func (d *Pbkdf2Key) GetKey() []byte {
	return d.Hash
}

func (d *Pbkdf2Key) GetSalt() []byte {
	return d.Salt
}

func (Pbkdf2Key) Key(value []byte, iter int, keyLen int, h func() hash.Hash) Key {
	salt := cryptography.NewRandom(8)
	hName := reflect.TypeOf(h())
	key := pbkdf2.Key(value, salt, iter, keyLen, h)
	return &Pbkdf2Key{
		Hash:     key,
		Salt:     salt,
		Algo:     "pbkdf2",
		Iter:     uint64(iter),
		KeyLen:   uint64(keyLen),
		HashType: hName.String(),
	}
}
