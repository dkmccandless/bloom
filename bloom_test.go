package bloom

import (
	"reflect"
	"testing"
)

var bitTests = []struct {
	f   *Filter
	ins []int
}{
	{&Filter{f: []byte{0}}, make([]int, 0)},
	{&Filter{f: []byte{1}}, []int{0}},
	{&Filter{f: []byte{2}}, []int{1}},
	{&Filter{f: []byte{3}}, []int{0, 1}},
	{&Filter{f: []byte{0, 0}}, make([]int, 0)},
	{&Filter{f: []byte{1, 0}}, []int{0}},
	{&Filter{f: []byte{2, 0}}, []int{1}},
	{&Filter{f: []byte{3, 0}}, []int{0, 1}},
	{&Filter{f: []byte{0, 1}}, []int{8}},
	{&Filter{f: []byte{0, 2}}, []int{9}},
	{&Filter{f: []byte{0, 3}}, []int{8, 9}},
	{&Filter{f: []byte{255}}, []int{0, 1, 2, 3, 4, 5, 6, 7}},
	{&Filter{f: []byte{72, 97, 80, 130, 1, 8, 0, 4}}, []int{3, 6, 8, 13, 14, 20, 22, 25, 31, 32, 43, 58}},
}

func TestBit(t *testing.T) {
	for _, test := range bitTests {
		m := make(map[int]struct{})
		for _, n := range test.ins {
			m[n] = struct{}{}
		}
		for n := 0; n < len(test.f.f)*8; n++ {
			var want int
			if _, ok := m[n]; ok {
				want = 1
			}
			if got := test.f.bit(n); got != want {
				t.Errorf("TestBit(%v, %v, %v): got %v, want %v", test.f.f, test.ins, n, got, want)
			}
		}
	}
}

func TestSetBit(t *testing.T) {
	for _, test := range bitTests {
		f := New(len(test.f.f), 1)
		for _, i := range test.ins {
			f.setBit(i)
		}
		for n := 0; n < len(f.f)*8; n++ {
			if got, want := f.bit(n), test.f.bit(n); got != want {
				t.Errorf("TestSetBit(%v, %v, %v): got %v, want %v", test.f.f, test.ins, n, got, want)
			}
		}
	}
}

func TestInsert(t *testing.T) {
	// SHA-256 test values from https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha_all.pdf
	// ""		e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	// "abc"	ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	//			248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
	for _, test := range []struct {
		s string
		h []uint16
	}{
		{"", []uint16{
			0xe3b0, 0xc442, 0x98fc, 0x1c14, 0x9afb, 0xf4c8, 0x996f, 0xb924,
			0x27ae, 0x41e4, 0x649b, 0x934c, 0xa495, 0x991b, 0x7852, 0xb855},
		},
		{"abc", []uint16{
			0xba78, 0x16bf, 0x8f01, 0xcfea, 0x4141, 0x40de, 0x5dae, 0x2223,
			0xb003, 0x61a3, 0x9617, 0x7a9c, 0xb410, 0xff61, 0xf200, 0x15ad},
		},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", []uint16{
			0x248d, 0x6a61, 0xd206, 0x38b8, 0xe5c0, 0x2693, 0x0c3e, 0x6039,
			0xa33c, 0xe459, 0x64ff, 0x2167, 0xf6ec, 0xedd4, 0x19db, 0x06c1},
		},
	} {
		for _, f := range []*Filter{
			New(512, 8),
			New(8192, 16),
		} {
			// Construct a map of precisely the bits that should be set
			m := make(map[int]int)
			for i := 0; i < f.k; i++ {
				n := int(test.h[i]) & (len(f.f)*8 - 1)
				m[n] = 1
			}

			f.Insert([]byte(test.s))

			for n := 0; n < len(f.f)*8; n++ {
				if got, want := f.bit(n), m[n]; got != want {
					t.Errorf("TestInsert(%v, k=%v, \"%v\", bit %x): got %v, want %v", len(f.f), f.k, test.s, n, got, want)
				}
			}
		}
	}
}

func TestMaybeContains(t *testing.T) {
	s := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, f := range []*Filter{
		// Test filters must be big enough to avoid collisions with high probability
		New(16, 3),
		New(128, 6),
		New(1024, 8),
		New(8192, 16),
	} {
		for n := 0; n <= len(s); n++ {
			for i := range s {
				if got := f.MaybeContains([]byte(s[i])); got != (i < n) {
					t.Errorf("TestMaybeContains(%v, %v: %v, %v); got %v, want %v", len(f.f), f.k, n, i, got, i < n)
				}
			}
			if n < len(s) {
				f.Insert([]byte(s[n]))
			}
		}
	}
}

var marshalTests = []struct {
	f    *Filter
	data []byte
}{
	{New(1, 1), []byte{0, 1}},
	{New(4, 1), []byte{0, 0, 0, 0, 1}},
	{New(4, 3), []byte{0, 0, 0, 0, 3}},
	{&Filter{f: []byte{255}, k: 4}, []byte{255, 4}},
	{&Filter{f: []byte{15, 23}, k: 4}, []byte{15, 23, 4}},
	{&Filter{f: []byte{1, 0, 1, 1, 2, 3, 5, 8}, k: 13}, []byte{1, 0, 1, 1, 2, 3, 5, 8, 13}},
}

func TestMarshalBinary(t *testing.T) {
	for _, test := range marshalTests {
		data, err := test.f.MarshalBinary()
		if err != nil {
			t.Errorf("TestMarshalBinary: %v", err)
		}
		if !reflect.DeepEqual(data, test.data) {
			t.Errorf("TestMarshalBinary: got %v, want %v", data, test.data)
		}
	}
}

func TestUnmarshalBinary(t *testing.T) {
	for _, test := range marshalTests {
		f := new(Filter)
		if err := f.UnmarshalBinary(test.data); err != nil {
			t.Errorf("TestUnmarshalBinary: %v", err)
		}
		if !reflect.DeepEqual(f, test.f) {
			t.Errorf("TestUnmarshalBinary: got %v, want %v", f, test.f)
		}
	}
}
