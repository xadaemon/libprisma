package kdf

// Key is the interface abstracting over the supported Key derivation functions in this package
type Key interface {
	// String convert this Key to a string in the form of `$algo;{any number of algorithm defined fields}`
	String() string
	// FromString read the string form of a Key into a Key implementer instance
	FromString(string) (Key, error)
	// Equals given the Key it's called on and a string, make a new Key with the same params as the referenced Key
	// and compare them in constant time
	Equals(other string) bool
	GetKey() []byte
	GetSalt() []byte
}
