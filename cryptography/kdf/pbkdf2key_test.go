package kdf_test

import (
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xadaemon/libprisma/cryptography/kdf"
)

func TestPbkdf2Key_Equals(t *testing.T) {
	someKey := "SomeKey"
	someKey2 := "SomeKey2"

	someKeyKdf := kdf.PbKdf2.KeyFromStr(someKey, 4096, 32, sha512.New)

	if !someKeyKdf.Equals(someKey) {
		t.Error("Failed to properly compare keys")
	} else if someKeyKdf.Equals(someKey2) {
		t.Error("Failed to properly compare keys")
	}
}

func TestParsePbkdf2KeyFromString(t *testing.T) {
	someKey := "SomeKey"
	someKeyKdf := kdf.PbKdf2.KeyFromStr(someKey, 4096, 32, sha512.New)
	someKeyStr := fmt.Sprintf("%s", someKeyKdf)
	v, _ := kdf.PbKdf2.FromString(someKeyStr)
	if !cmp.Equal(someKeyKdf, v) {
		t.Error("Decoded KeyFromStr object from string doesn't match the original")
	}
}
