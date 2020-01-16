// Package bloom implements a Bloom filter data structure.
package bloom

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math/bits"
)

// Filter represents a Bloom filter. Filter satisfies the encoding.BinaryMarshaler and BinaryUnmarshaler interfaces.
// The zero value represents an empty filter of size 0 that uses 0 hash values.
// Current implementations of Insert and Contains require len(f) <= 2^16 bits and k <= 16.
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

// hashBits returns the base 2 logarithm of the size of the filter in bits.
// This is the number of hash bits required to index any bit in the filter.
// TODO: Handle filter size not a power of 2
func (f *Filter) hashBits() int {
	if bits.OnesCount(uint(len(f.f))) != 1 {
		log.Fatal("hashBits: filter size not a power of 2")
	}
	return bits.TrailingZeros64(uint64(len(f.f)) * 8)
}

// New returns a Filter of size b bytes that uses k hash values.
func New(b, k int) *Filter { return &Filter{make([]byte, b), k} }

// Insert inserts data into f's set.
func (f *Filter) Insert(data []byte) {
	hash := sha256.Sum256(data)
	for h := 0; h < f.k; h++ {
		// i is constructed from two bytes, limiting filter size to 2^16 bits.
		// The factor of 2 also limits f.k to 16 hash values.
		i := binary.BigEndian.Uint16(hash[2*h:]) & (1<<uint(f.hashBits()) - 1)
		f.setBit(int(i))
	}
}

// Contains reports whether data is in f's set.
// If Contains returns true, a false positive is possible,
// but if Contains returns false, data is definitely not in the set.
func (f *Filter) Contains(data []byte) bool {
	hash := sha256.Sum256(data)
	for h := 0; h < f.k; h++ {
		// i is constructed from two bytes, limiting filter size to 2^16 bits.
		// The factor of 2 also limits f.k to 16 hash values.
		i := binary.BigEndian.Uint16(hash[2*h:]) & (1<<uint(f.hashBits()) - 1)
		if f.bit(int(i)) == 0 {
			return false
		}
	}
	return true
}

// MarshalBinary marshals f into a binary form. It satisfies the encoding.BinaryMarshaler interface.
func (f *Filter) MarshalBinary() (data []byte, err error) {
	// The filter, followed by the number of hash functions expressed as a single byte
	return append(f.f, byte(f.k)), nil
}

// UnmarshalBinary unmarshals a binary representation of a Filter and stores the representation in f.
// It overwrites any existing data in f.
// UnmarshalBinary satisfies the encoding.BinaryUnmarshaler interface.
func (f *Filter) UnmarshalBinary(data []byte) (err error) {
	l := len(data)
	if l == 0 {
		return errors.New("MarshalBinary: empty data slice")
	}
	f.f = append(make([]byte, 0, l-1), data[:l-1]...)
	f.k = int(data[l-1])
	return nil
}
