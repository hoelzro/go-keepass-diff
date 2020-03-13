package main

// only implements the 256-bit Salsa20

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	Rounds = 20
)

type Salsa20Reader struct {
	innerReader io.Reader
	state       [16]uint32
	output      [16]uint32
	offset      int
}

func rotl(a, b uint32) uint32 {
	return (a << b) | (a >> (32 - b))
}

func qr(a, b, c, d *uint32) {
	*b ^= rotl(*a+*d, 7)
	*c ^= rotl(*b+*a, 9)
	*d ^= rotl(*c+*b, 13)
	*a ^= rotl(*d+*c, 18)
}

func salsa20Block(dst, src []uint32) {
	var x [16]uint32 // XXX var name?

	copy(x[:], src[:])

	for i := 0; i < Rounds; i += 2 {
		// odd round
		qr(&x[0], &x[4], &x[8], &x[12])
		qr(&x[5], &x[9], &x[13], &x[1])
		qr(&x[10], &x[14], &x[2], &x[6])
		qr(&x[15], &x[3], &x[7], &x[11])

		// even round
		qr(&x[0], &x[1], &x[2], &x[3])
		qr(&x[5], &x[6], &x[7], &x[4])
		qr(&x[10], &x[11], &x[8], &x[9])
		qr(&x[15], &x[12], &x[13], &x[14])
	}

	for i := 0; i < 16; i++ {
		dst[i] = x[i] + src[i]
	}
}

// XXX put me in the reader or something
func encryptBytes(r *Salsa20Reader, dst, src []byte) {
	// XXX assert len(dst) == len(src)?
	var outputBytes [4]byte
	offset := 0

	for {
		if offset >= len(dst) {
			return
		}

		if r.offset == 0 {
			salsa20Block(r.output[:], r.state[:])
			r.state[8]++
			if r.state[8] == 0 {
				r.state[9]++
			}
		}

		// we know r.offset is 0 here, so you don't need to do the pre-warming of outputBytes

		// XXX unroll this into something less shitty
		for ; r.offset < 64; r.offset, offset = r.offset+1, offset+1 {
			if offset >= len(dst) {
				return
			}

			// XXX use bitwise ops? (0b11)
			//if r.offset%4 == 0 {
			// XXX avoid function call? (it might get inlined)
			binary.LittleEndian.PutUint32(outputBytes[:], r.output[r.offset/4])
			//}
			dst[offset] = src[offset] ^ outputBytes[r.offset%4]
		}
		r.offset = 0
	}
}

func NewSalsa20Reader(r io.Reader, key, iv []byte) (*Salsa20Reader, error) {
	if len(key) != 32 {
		return nil, errors.New("keys must be 32 bytes long")
	}

	if len(iv) != 8 {
		return nil, errors.New("IVs must be 8 bytes long")
	}

	var initialState [16]uint32

	// nothing-up-my-sleeve number
	nothingUpMySleeve := bytes.NewReader([]byte("expand 32-byte k"))
	binary.Read(nothingUpMySleeve, binary.LittleEndian, &initialState[0])
	binary.Read(nothingUpMySleeve, binary.LittleEndian, &initialState[5])
	binary.Read(nothingUpMySleeve, binary.LittleEndian, &initialState[10])
	binary.Read(nothingUpMySleeve, binary.LittleEndian, &initialState[15])

	// nonce/IV
	ivBytes := bytes.NewReader(iv)
	binary.Read(ivBytes, binary.LittleEndian, &initialState[6])
	binary.Read(ivBytes, binary.LittleEndian, &initialState[7])

	// stream position
	initialState[8] = 0
	initialState[9] = 0

	// key
	keyBytes := bytes.NewReader(key)
	binary.Read(keyBytes, binary.LittleEndian, &initialState[1])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[2])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[3])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[4])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[11])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[12])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[13])
	binary.Read(keyBytes, binary.LittleEndian, &initialState[14])

	return &Salsa20Reader{
		innerReader: r,
		state:       initialState,
	}, nil
}

func (s *Salsa20Reader) Read(out []byte) (int, error) {
	// XXX can we use the same buffer?
	ciphertext := make([]byte, len(out))
	bytesRead, err := s.innerReader.Read(ciphertext)
	if err != nil {
		return 0, err
	}
	// XXX should we be doing the 64-byte chunking here?
	encryptBytes(s, out, ciphertext)
	return bytesRead, nil
}
