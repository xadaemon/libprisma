package symmetrical_test

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/xadaemon/libprisma/cryptography/symmetrical"
)

func TestSecureAES(t *testing.T) {
	plainText := []byte("This is a test string, it is not very long but it is long enough to test the encryption and decryption functions")
	secureAes, err := symmetrical.NewSecureAES([]byte("superSecretKey"), symmetrical.AES256)
	if err != nil {
		t.Errorf("Error creating SecureAES: %v", err)
	}

	encrypted, err := secureAes.EncryptToBytes(plainText)
	if err != nil {
		t.Fatalf("Error encrypting data: %v", err)
	}

	if len(encrypted) < len(plainText) {
		t.Errorf("Encrypted data is not at least the size of plaintext")
		t.FailNow()
	}

	secureAes, err = symmetrical.NewSecureAES([]byte("superSecretKey"), symmetrical.AES256)
	if err != nil {
		t.Errorf("Error creating SecureAES: %v", err)
	}

	decrypted, err := secureAes.DecryptFromBytes(encrypted)
	if err != nil {
		t.Errorf("Error decrypting data: %v", err)
	}

	secureAes, err = symmetrical.NewSecureAES([]byte("superSecretKey"), symmetrical.AES256)
	if err != nil {
		t.Errorf("Error creating SecureAES: %v", err)
	}

	if cmp.Equal(plainText, decrypted) == false {
		fmt.Println(string(plainText), "!=", string(decrypted))
		t.Errorf("Decrypted data does not match original data")
		t.FailNow()
	}

	// test detect tampering with capsule
	encrypted[0] = encrypted[0] ^ 0xFF
	_, err = secureAes.DecryptFromBytes(encrypted)
	if err == nil {
		t.Errorf("Tampered data was decrypted successfully")
	}
	encrypted[0] = encrypted[0] ^ 0xFF
	// test detect tampering with the ciphertext
	var cap symmetrical.AESCapsule
	cbor.Unmarshal(encrypted, &cap)
	for i, d := range cap.Ciphertext {
		cap.Ciphertext[i] = d ^ 0xFF
	}
	tampered, _ := cbor.Marshal(cap)
	_, err = secureAes.DecryptFromBytes(tampered)
	if err == nil {
		t.Errorf("Tampered data was decrypted successfully")
	}
}
