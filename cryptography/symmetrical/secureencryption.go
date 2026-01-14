package symmetrical

import (
	"errors"
	"io"
)

type CypherError int

const (
	ErrInvalidKeyLength CypherError = iota
	ErrTagMismatch      CypherError = iota
	ErrorUnknown        CypherError = iota
)

func (e CypherError) String() string {
	switch {
	case errors.Is(e, ErrInvalidKeyLength):
		return "ErrInvalidKeyLength"
	case errors.Is(e, ErrTagMismatch):
		return "ErrTagMismatch"
	case errors.Is(e, ErrorUnknown):
		return "ErrorUnknown"
	default:
		return "ErrorUnknown"
	}
}

func (e CypherError) Error() string {
	return e.String()
}

func FindNextDiv(n int, bs int) int {
	for {
		if n%bs == 0 {
			return n
		}
		n += 1
	}
}

type SecureCypher interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	GetTag() []byte
	GetTagSize() int
	GetBlockSize() int
	GetIV() []byte
	SetIV(iv []byte)
	GetIvSize() int
	TagPlusIVSize() int
	GetKeyThumbprint() []byte
	CheckKeyThumbprint(thumbprint []byte) bool
	Reset()
	FullReset()
	Dispose()
	EncryptToBytes(data []byte) ([]byte, error)
	DecryptFromBytes(data []byte) ([]byte, error)
}

type StreamEncryptor struct {
	cypher     SecureCypher
	drain      io.Writer
	isFinished bool
}

func NewSecureStreamEncryptor(cypher SecureCypher, drain io.Writer) *StreamEncryptor {
	return &StreamEncryptor{
		cypher:     cypher,
		drain:      drain,
		isFinished: false,
	}
}

// Write encrypts the data and writes it to the underlying writer, it returns the number of bytes written and an error if any.
// if len data is < than the cypher's block size, it is considered the last block and the stream is finished can't be written to anymore.
// attempting further writes will return EOF error.
func (s *StreamEncryptor) Write(data []byte) (int, error) {
	if s.isFinished {
		return 0, io.EOF
	}

	if len(data) == 0 {
		s.isFinished = true
		return 0, nil
	} else if len(data) < s.cypher.GetBlockSize() {
		s.isFinished = true
	}

	d, err := s.cypher.Encrypt(data)
	if err != nil {
		return 0, err
	}
	wn, err := s.drain.Write(d)
	if err != nil {
		return 0, err
	}

	return wn, nil
}

func (s *StreamEncryptor) WriteTag() error {
	s.isFinished = true
	tw, err := s.drain.Write(s.cypher.GetTag())
	if err != nil {
		return err
	}
	if tw != s.cypher.GetTagSize() {
		return errors.New("written bytes is not equal to tag size")
	}
	return nil
}

func (s *StreamEncryptor) Close() error {
	return s.WriteTag()
}

func (s *StreamEncryptor) GetTag() []byte {
	return s.cypher.GetTag()
}

func (s *StreamEncryptor) Reset(drain io.Writer) {
	s.cypher.Reset()
	s.drain = drain
}
