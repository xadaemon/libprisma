package ed25519_test

import (
	"encoding/base64"
	"testing"

	"github.com/xadaemon/libprisma/cryptography"
	"github.com/xadaemon/libprisma/cryptography/ed25519"
)

var testData = "EQTZHq7KUG6jLFJTioDvbweGRz/pRpBnoWxaEeiaJGg0lwvoB+r3mcFLLQq30hm/MT+t/GYlG3LN8IRxOeosZmmTI4EE3qt3bMlxCSH8h0xjysUcjM0kNMH2/En5/sRe9cF+wZNcy1i5LF/1y2i3KRGUQBRUQT1PrOVuAGx01hY="

func TestEd25519(t *testing.T) {
	data, _ := base64.RawStdEncoding.DecodeString(testData)
	ed25519Util := ed25519.Ed25519Util{}
	privateKey := ed25519Util.NewKey()
	publicKey := ed25519Util.PublicFromPrivateKey(privateKey)
	signature, err := ed25519Util.Sign(privateKey, data)
	if err != nil {
		t.Errorf("Sign failed: %v", err)
	}
	// try to verify the sig
	if !ed25519Util.Verify(publicKey, signature, data) {
		t.Errorf("Signature verification failed")
	}

	// Test verification with wrong data
	data = cryptography.NewRandom(32)
	if ed25519Util.Verify(publicKey, signature, data) {
		t.Errorf("Signature verification should have failed")
	}
}
