// Package bloom implements a Bloom filter data structure.
package bloom

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// Filter is a Bloom filter, which represents a set of items and provides a probabilistic test for membership.
// Filter satisfies the encoding.BinaryMarshaler and BinaryUnmarshaler interfaces.
// The zero value represents an empty filter of size 0 that uses 0 hash values.
type Filter struct {
	f []byte
	k int
}

// bit returns the filter's nth bit.
func (f *Filter) bit(n int) int {
	b, i := n/8, n%8
	return int(f.f[b]>>uint(i)) & 1
}

// setBit sets the filter's nth bit to 1.
func (f *Filter) setBit(n int) {
	b, i := n/8, n%8
	f.f[b] |= 1 << uint(i)
}

// New returns a Filter of size b bytes that uses k hash values.
// It panics if b is not a power of 2 in the range [1, 8192] or k is not in the range [1, 16].
func New(b, k int) *Filter {
	if b <= 0 || b > 8192 {
		panic("New: Filter size out of range")
	}
	if bits.OnesCount(uint(b)) != 1 {
		panic("New: Filter size not a power of 2")
	}
	if k <= 0 || k > 16 {
		panic("New: Number of hash values out of range")
	}
	return &Filter{make([]byte, b), k}
}

// Insert inserts item into f's set.
func (f *Filter) Insert(item []byte) {
	hash := sha256.Sum256(item)
	for h := 0; h < f.k; h++ {
		// SHA-256 hashes are 32 bytes long, so constructing i from a pair of bytes yields a maximum of 16 hash values,
		// each indexing a filter of size at most 65536 bits.
		i := int(binary.BigEndian.Uint16(hash[2*h:])) & (len(f.f)*8 - 1)
		f.setBit(i)
	}
}

// MaybeContains reports whether item is probably in f's set.
// If MaybeContains returns true, a false positive is possible,
// but if MaybeContains returns false, item is definitely not in the set.
func (f *Filter) MaybeContains(item []byte) bool {
	hash := sha256.Sum256(item)
	for h := 0; h < f.k; h++ {
		// SHA-256 hashes are 32 bytes long, so constructing i from a pair of bytes yields a maximum of 16 hash values,
		// each indexing a filter of size at most 65536 bits.
		i := int(binary.BigEndian.Uint16(hash[2*h:])) & (len(f.f)*8 - 1)
		if f.bit(int(i)) == 0 {
			return false
		}
	}
	return true
}

// MarshalBinary marshals f into a binary form. It satisfies the encoding.BinaryMarshaler interface.
func (f *Filter) MarshalBinary() ([]byte, error) {
	// The filter, followed by the number of hash values expressed as a single byte
	return append(f.f, byte(f.k)), nil
}

// UnmarshalBinary unmarshals a binary representation of a Filter and stores the representation in f.
// If the size of the unmarshaled Filter in bytes is not a power of 2 in the range [1, 8192]
// or the unmarshaled number of hash values is not in the range [1, 16],
// UnmarshalBinary returns an error without modifying the contents of f.
// Otherwise, it overwrites any existing data in f and returns nil.
// UnmarshalBinary satisfies the encoding.BinaryUnmarshaler interface.
func (f *Filter) UnmarshalBinary(data []byte) error {
	l := len(data)
	if l == 0 {
		return errors.New("UnmarshalBinary: empty data slice")
	}
	if bits.OnesCount(uint(l-1)) != 1 {
		return fmt.Errorf("UnmarshalBinary: Filter size %v bytes not a power of 2", l-1)
	}
	k := int(data[l-1])
	if k <= 0 || k > 16 {
		panic("UnmarshalBinary: Number of hash values out of range")
	}
	f.f = append(make([]byte, 0, l-1), data[:l-1]...)
	f.k = k
	return nil
}
