package cryptography

import (
	"crypto/aes"
	crand "crypto/rand"
	"crypto/sha256"
	"math/rand/v2"
)

type Blocker struct {
	blockSize int
	last      int
	buff      []byte
}

func NewBlocker(blockSize int, data []byte) *Blocker {
	return &Blocker{
		blockSize: blockSize,
		last:      0,
		buff:      data,
	}
}

func (b *Blocker) Next() (int, []byte) {
	if b.last*b.blockSize >= len(b.buff) {
		return 0, nil
	}
	first := b.last * b.blockSize
	last := min((b.last+1)*b.blockSize, len(b.buff))
	b.last++
	block := make([]byte, b.blockSize)
	if first-last == 0 {
		return 0, []byte{}
	}
	ret := copy(block, b.buff[first:last])
	if ret < b.blockSize {
		ANSIPad(block, uint8(b.blockSize), uint8(ret), true)
	}
	return aes.BlockSize, block
}

// Secure compare is a comparison function that never short-circuits, for use
// in timing attack sensitive contexts.
//
// **Note** however that because it never short circuits it can be abused to
// inflict denial of service type attacks if the inputs are not strictly the
// output of hashing functions.
func SecureCompare(a []byte, b []byte) bool {
	var res byte
	if len(a) != len(b) {
		if len(a) < len(b) {
			for i := range a {
				res ^= a[i] ^ a[max(i-1, 0)]
			}
		} else {
			for i := range a {
				res ^= b[i] ^ b[max(i-1, 0)]
			}
		}
		return max(1, res) == 0
	}
	for i := range a {
		res ^= a[i] ^ b[i]
	}
	return res == 0
}

type SeededPRNG struct {
	iter uint64
	rand *rand.Rand
}

func NewSeededPRNG(seed []byte, discard uint) *SeededPRNG {
	h := sha256.New()
	h.Write(seed)
	seed = h.Sum(seed)
	g := &SeededPRNG{
		iter: 0,
		rand: rand.New(rand.NewChaCha8([32]byte(seed))),
	}
	if discard > 0 {
		for _ = range discard {
			g.rand.Uint64()
		}
	}
	return g
}

func (g *SeededPRNG) GetBytes(n int) []byte {
	out := make([]byte, n)
	g.FillBuffer(out)
	return out
}

func (g *SeededPRNG) FillBuffer(buff []byte) {
	for i := range buff {
		buff[i] = byte(g.rand.UintN(256))
	}
}

func SeededRandomData(seed []byte, n int) []byte {
	h := sha256.New()
	h.Write(seed)
	seed = h.Sum(seed)
	rng := rand.New(rand.NewChaCha8([32]byte(seed)))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(rng.UintN(256))
	}
	return out
}

// NewRandom generates a random salt of the specified length and returns it as a Salt type. If an error occurs
// while generating the salt or the generated salt length does not match the specified length, a panic is raised
// with an error message.
func NewRandom(l int) []byte {
	salt := make([]byte, l)
	n, err := crand.Read(salt)
	if n != l || err != nil {
		panic("Error getting randomness, check your OS true randomness source!")
	}
	return salt
}

type PaddingFunc func(data []byte, bs uint8, ds uint8, rand_pad bool) int

func PKCSPad(data []byte, bs uint8, ds uint8, _ bool) int {
	if ds == bs {
		return 0
	}
	needed := uint8(bs - ds)
	for i := 0; i < int(needed); i = i + 1 {
		data[int(ds)+i] = needed
	}
	return int(needed)
}

func ANSIPad(data []byte, bs uint8, ds uint8, pad_rand bool) int {
	if ds == bs {
		return 0
	}
	needed := bs - ds
	if pad_rand {
		crand.Read(data[ds:])
	} else {
		for i := 0; i < int(needed); i = i + 1 {
			data[int(ds)+i] = needed
		}
	}
	data[len(data)-1] = byte(needed)
	return int(needed)
}

// Only one function is needed to strip the padding as in both supported
// schemes the last byte will be the padding length
func StripPadding(dest []byte, block []byte) {
	pad_len := block[len(block)]
	copy(dest, block[:pad_len])
}
