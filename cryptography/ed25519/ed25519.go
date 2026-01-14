package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	_ "crypto/sha512"

	"github.com/xadaemon/libprisma/cryptography"
)

type Ed25519Util struct{}

func (Ed25519Util) NewKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(cryptography.NewRandom(32))
}

func (Ed25519Util) Sign(k ed25519.PrivateKey, message []byte) ([]byte, error) {
	hx := crypto.SHA512.New()
	var hd []byte
	if n, err := hx.Write(message); err != nil {
		return nil, err
	} else if n != len(message) {
		return nil, fmt.Errorf("hasher read %d and not the expected %d", n, len(message))
	}
	hd = hx.Sum([]byte{})
	return k.Sign(nil, hd, crypto.SHA512)
}

func (Ed25519Util) Verify(k ed25519.PublicKey, sig []byte, message []byte) bool {
	hx := crypto.SHA512.New()
	var hd []byte
	hx.Write(message)
	hd = hx.Sum([]byte{})
	err := ed25519.VerifyWithOptions(k, hd, sig, &ed25519.Options{Hash: crypto.SHA512, Context: ""})
	return err == nil
}

func (Ed25519Util) PublicFromPrivateKey(k ed25519.PrivateKey) ed25519.PublicKey {
	return k.Public().(ed25519.PublicKey)
}
