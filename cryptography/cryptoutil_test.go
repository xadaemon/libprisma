package cryptography_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/xadaemon/libprisma/cryptography"
)

const TEST_ITERS int = 1_000_000
const TEST_BSIZE uint8 = 64

func TestANSIPad(t *testing.T) {
	for i := 0; i < TEST_ITERS; i = i + 1 {
		bc := uint8(rand.UintN(uint(TEST_BSIZE)))
		data := make([]byte, TEST_BSIZE)
		expect_pad := bc < TEST_BSIZE
		expected_padding := TEST_BSIZE - bc
		pad := cryptography.ANSIPad(data, TEST_BSIZE, bc, true)
		if !expect_pad && len(data) != int(bc) {
			fmt.Println("padding added when it was not needed", bc, expect_pad)
			t.FailNow()
		} else if pad != int(expected_padding) {
			fmt.Println("expected", expected_padding, "got", pad)
			t.FailNow()
		} else if len(data) != int(TEST_BSIZE) {
			fmt.Println("expected", TEST_BSIZE, "got", len(data))
			t.FailNow()
		}
		pad = cryptography.ANSIPad(data, TEST_BSIZE, bc, false)
		if !expect_pad && len(data) != int(bc) {
			fmt.Println("padding added when it was not needed", bc, expect_pad)
			t.FailNow()
		} else if pad != int(expected_padding) {
			fmt.Println("expected", TEST_BSIZE, "got", len(data))
			t.FailNow()
		}
	}
}

func TestPKCSPad(t *testing.T) {
	for i := 0; i < TEST_ITERS; i = i + 1 {
		bc := uint8(rand.UintN(uint(TEST_BSIZE)))
		data := make([]byte, TEST_BSIZE)
		expect_pad := bc < TEST_BSIZE
		expected_padding := TEST_BSIZE - bc
		pad := cryptography.PKCSPad(data, TEST_BSIZE, bc, true)
		if !expect_pad && len(data) != int(bc) {
			fmt.Println("padding added when it was not needed", bc, expect_pad)
			t.FailNow()
		} else if pad != int(expected_padding) {
			fmt.Println("expected", expected_padding, "got", pad)
			t.FailNow()
		} else if len(data) != int(TEST_BSIZE) {
			fmt.Println("expected", TEST_BSIZE, "got", len(data))
			t.FailNow()
		}
	}
}
