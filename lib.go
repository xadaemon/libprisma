package libprisma

import "io"

// Result is a generic type that can hold a value of type T or an error
type Result[T any] struct {
	value T
	err   error
}

func Ok[T any](v T) Result[T] {
	return Result[T]{value: v, err: nil}
}

func Err[T any](err error) Result[T] {
	return Result[T]{err: err}
}

// May wraps a call to some function that returns value or err and creates a result
func May[T any](v T, err error) Result[T] {
	if err != nil {
		return Err[T](err)
	} else {
		return Ok(v)
	}
}

// ValueOrPanic returns T if there is no error, otherwise panics
func (r Result[T]) ValueOrPanic() T {
	if r.err != nil {
		panic(r.err)
	}
	return r.value
}

// Unwrap returns the value and error of the Result in the usual Go way
func (r Result[T]) Unwrap() (T, error) {
	return r.value, r.err
}

// IsErr returns true if the Result has an error
func (r Result[T]) IsErr() bool {
	return r.err != nil
}

// ValueOr returns the value if there is no error, otherwise returns the default value
func (r Result[T]) ValueOr(def T) T {
	if r.err != nil {
		return def
	}
	return r.value
}

// ValueOrFunc returns the value if there is no error, otherwise returns the result of the function `f`
func (r Result[T]) ValueOrFunc(f func() T) T {
	if r.err != nil {
		return f()
	}
	return r.value
}

// Map takes a slice of T and a function that returns a Result[T] applies `f` to `s` and returns a slice of Result[T]
func Map[S ~[]T, T any](s S, f func(T) Result[T]) []Result[T] {
	r := make([]Result[T], len(s))
	for i, vals := range s {
		r[i] = f(vals)
	}
	return r
}

// Collect takes a slice of Result[T] and returns a slice of T or the first error encountered
func Collect[S ~[]Result[T], T any](s S) ([]T, error) {
	r := make([]T, len(s))
	for i, val := range s {
		if val.err != nil {
			return []T{}, val.err
		}
		r[i] = val.value
	}
	return r, nil
}

// Switch takes a slice of T and a function that returns a bool,
// it will apply `f` to each T in `s` and will switch T into one of two slices based on the result of `f`
func Switch[S ~[]T, T any](s S, f func(T) bool) ([]T, []T) {
	var t []T
	var e []T
	for _, val := range s {
		if f(val) {
			t = append(t, val)
		} else {
			e = append(e, val)
		}
	}
	return t, e
}

// StreamingSwitch takes a channel of T and two channels of T and a function that returns a bool,
// it will apply `f` to each T in `s` and will switch each T from `s` into one of two channels based on the result of `f`
// until `s` is closed
func StreamingSwitch[T any](s chan T, sinkA chan T, sinkB chan T, f func(T) bool) {
	defer close(sinkA)
	defer close(sinkB)
	for {
		select {
		case val, ok := <-s:
			if !ok {
				return
			}
			if f(val) {
				sinkA <- val
			} else {
				sinkB <- val
			}
		}
	}
}

// Stream takes many slices of T and emits each element in the slices in order on the channel `ch`, closing the channel when done
func Stream[S ~[]T, T any](ch chan T, s ...S) {
	defer close(ch)
	for _, vals := range s {
		for _, val := range vals {
			ch <- val
		}
	}
}

type StreamedChunk struct {
	Chunk []byte
	Read  int
	Done  bool
	Err   error
}

func StreamReader(ch chan *StreamedChunk, r io.Reader, chunkSize int) {
	defer close(ch)
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			ch <- &StreamedChunk{
				Chunk: buf[:n],
				Read:  n,
				Err:   err,
			}
		}
		if n == 0 || err == io.EOF {
			ch <- &StreamedChunk{
				Chunk: nil,
				Read:  0,
				Done:  true,
				Err:   err,
			}
			return
		}
		if err != nil {
			ch <- &StreamedChunk{
				Chunk: nil,
				Read:  0,
				Err:   err,
			}
			return
		}
	}
}

// Sieve takes a slice of Result[T] and returns a slice of T with the errors removed and a slice of errors if any
func Sieve[S ~[]Result[T], T any](s S) ([]T, []error) {
	var vals []T
	var errs []error
	for _, val := range s {
		if val.err != nil {
			errs = append(errs, val.err)
			continue
		}
		vals = append(vals, val.value)
	}
	return vals, errs
}

// MapValToKey takes a map with keys of type K and values of type V, and returns a new map
// with keys and values swapped. The values in the original map should be comparable.
func MapValToKey[K comparable, V comparable](m map[K]V) map[V]K {
	r := map[V]K{}
	for k, v := range m {
		r[v] = k
	}

	return r
}
