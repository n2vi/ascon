// Copyright©2019 Eric Grosse n2vi.com/BSD2.txt

// Package ascon80pq implements the system described at https://ascon.iaik.tugraz.at.
// This lightweight AuthenticatedEncryptionAssociatedData cipher uses a 20 byte key
// and 16 byte nonce, producing ciphertext of the same length as the plaintext plus
// a 16 byte authentication tag.
package ascon80pq // import "github.com/n2vi/ascon/ascon80pq"

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/bits"
)

// Function Encrypt reads plaintext from the input stream, encrypts using key,
// and writes ciphertext || tag to the output stream.  ad may be empty.
// The nonce must not be reused!
func Encrypt(ciphertext io.Writer, plaintext io.Reader, ad, nonce, key []byte) {
	if len(nonce) != 16 || len(key) != 20 {
		log.Fatal("recheck lengths of nonce and key")
	}
	K0 := uint64(binary.BigEndian.Uint32(key[0:4]))
	K1 := binary.BigEndian.Uint64(key[4:12])
	K2 := binary.BigEndian.Uint64(key[12:20])
	N0 := binary.BigEndian.Uint64(nonce[0:8])
	N1 := binary.BigEndian.Uint64(nonce[8:16])
	IV := uint64(0xa0400c06) << 32
	rbuf := bufio.NewReader(plaintext)
	wbuf := bufio.NewWriter(ciphertext)

	// Initialization phase
	var s state
	s.x0 = IV | K0
	s.x1 = K1
	s.x2 = K2
	s.x3 = N0
	s.x4 = N1
	s = perm12(s)
	s.x2 ^= K0
	s.x3 ^= K1
	s.x4 ^= K2

	// Associated Data phase
	if len(ad) > 0 {
		for len(ad) >= 8 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s = perm6(s)
			ad = ad[8:]
		}
		s.x0 ^= bigendianUint64(ad[0:])
		s.x0 ^= uint64(0x80) << (56 - 8*len(ad))
		s = perm6(s)
	}
	s.x4 ^= 1

	// Plaintext phase
	p := make([]byte, 8)
	c := make([]byte, 8)
	var errp error
	var np int // number of valid bytes in p
	for errp == nil {
		n, errp := rbuf.Read(p[np:])
		np += n
		if errp == io.EOF {
			if np < 8 {
				break
			}
		} else if errp != nil {
			log.Fatal(errp)
		} else if np < 8 {
			continue // try reading again; maybe more will become available
		}
		s.x0 ^= binary.BigEndian.Uint64(p)
		binary.BigEndian.PutUint64(c, s.x0)
		n, err := wbuf.Write(c)
		chk(err)
		if n != 8 {
			log.Fatal("short write of ciphertext without err?")
		}
		s = perm6(s)
		np = 0
		if errp == io.EOF {
			break
		}
	}
	s.x0 ^= bigendianUint64(p[:np])
	s.x0 ^= uint64(0x80) << (56 - 8*np)
	bigendianPutUint64(c, s.x0, np)
	_, err := wbuf.Write(c[:np])
	chk(err)

	// Finalization phase
	s.x1 ^= K0<<32 | K1>>32
	s.x2 ^= K1<<32 | K2>>32
	s.x3 ^= K2 << 32
	s = perm12(s)
	s.x3 ^= K1
	s.x4 ^= K2
	binary.BigEndian.PutUint64(c, s.x3)
	_, err = wbuf.Write(c)
	chk(err)
	binary.BigEndian.PutUint64(c, s.x4)
	_, err = wbuf.Write(c)
	chk(err)
	err = wbuf.Flush()
	chk(err)
}

var BadVerify = errors.New("ASCON decrypt verify failed! Do not use any partial results.")

// Function Decrypt reads nonce and ciphertext from the input stream, decrypts using key
// and ad, and writes plaintext to the output stream. If verification at the end fails, error will
// be non-nil and caller should ignore the plaintext, including wiping any partial results
// already sent to disk. (It would be better to do that here, but is infeasible in one pass.
// For sample use, see command paxz. See also imperialviolet.org 2014/06/27.)
func Decrypt(plaintext io.Writer, ciphertext io.Reader, ad, key []byte) error {
	if len(key) != 20 {
		log.Fatal("recheck length of key")
	}
	rbuf := bufio.NewReader(ciphertext)
	wbuf := bufio.NewWriter(plaintext)

	nonce := make([]byte, 16)
	n, err := rbuf.Read(nonce)
	chk(err)
	if n != 16 {
		log.Fatal("short read of ciphertext without err?")
	}
	K0 := uint64(binary.BigEndian.Uint32(key[0:4]))
	K1 := binary.BigEndian.Uint64(key[4:12])
	K2 := binary.BigEndian.Uint64(key[12:20])
	N0 := binary.BigEndian.Uint64(nonce[0:8])
	N1 := binary.BigEndian.Uint64(nonce[8:16])
	IV := uint64(0xa0400c06) << 32

	// Initialization phase
	var s state
	s.x0 = IV | K0
	s.x1 = K1
	s.x2 = K2
	s.x3 = N0
	s.x4 = N1
	s = perm12(s)
	s.x2 ^= K0
	s.x3 ^= K1
	s.x4 ^= K2

	// Associated Data phase
	if len(ad) > 0 {
		for len(ad) >= 8 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s = perm6(s)
			ad = ad[8:]
		}
		s.x0 ^= bigendianUint64(ad[0:])
		s.x0 ^= uint64(0x80) << (56 - 8*len(ad))
		s = perm6(s)
	}
	s.x4 ^= 1

	// Plaintext phase
	c := make([]byte, 24)
	p := make([]byte, 8)
	var errc error
	var nc int // number of valid bytes in c
	for errc == nil {
		n, errc := rbuf.Read(c[nc:])
		nc += n
		if errc == io.EOF {
			if nc < 24 {
				break
			}
		} else if errc != nil {
			log.Fatal(errc)
		} else if nc < 24 {
			continue // try reading again; maybe more will become available
		}
		c0 := binary.BigEndian.Uint64(c[:8])
		binary.BigEndian.PutUint64(p, s.x0^c0)
		s.x0 = c0
		n, err := wbuf.Write(p)
		chk(err)
		if n != 8 {
			log.Fatal("short write of plaintext without err?")
		}
		s = perm6(s)
		copy(c, c[8:])
		nc = 16
		if errc == io.EOF {
			break
		}
	}
	nc -= 16 // The rest of the bytes are auth tag.
	if nc < 0 {
		log.Fatalf("can't happen! nc=%d", nc)
	}
	c0 := bigendianUint64(c[:nc])
	tag0 := binary.BigEndian.Uint64(c[nc : nc+8])
	tag1 := binary.BigEndian.Uint64(c[nc+8 : nc+16])
	bigendianPutUint64(p, s.x0^c0, nc)
	_, err = wbuf.Write(p[:nc])
	chk(err)
	err = wbuf.Flush()
	chk(err)
	s.x0 &= uint64(0xffffffffffffffff) >> (8 * nc)
	s.x0 |= c0
	s.x0 ^= uint64(0x80) << (56 - 8*nc)

	// Finalization phase
	s.x1 ^= K0<<32 | K1>>32
	s.x2 ^= K1<<32 | K2>>32
	s.x3 ^= K2 << 32
	s = perm12(s)
	s.x3 ^= K1
	s.x4 ^= K2
	if tag0 != s.x3 || tag1 != s.x4 {
		return BadVerify
	}
	return nil
}

type state struct{ x0, x1, x2, x3, x4 uint64 }

func round(C uint8, s state) state {
	var t state
	// addition of round constant
	s.x2 ^= uint64(C)
	// substitution layer S-box
	s.x0 ^= s.x4
	s.x4 ^= s.x3
	s.x2 ^= s.x1
	t.x0 = ^s.x0
	t.x1 = ^s.x1
	t.x2 = ^s.x2
	t.x3 = ^s.x3
	t.x4 = ^s.x4
	t.x0 &= s.x1
	t.x1 &= s.x2
	t.x2 &= s.x3
	t.x3 &= s.x4
	t.x4 &= s.x0
	s.x0 ^= t.x1
	s.x1 ^= t.x2
	s.x2 ^= t.x3
	s.x3 ^= t.x4
	s.x4 ^= t.x0
	s.x1 ^= s.x0
	s.x0 ^= s.x4
	s.x3 ^= s.x2
	s.x2 = ^s.x2
	// linear diffusion layer P-box
	s.x0 ^= bits.RotateLeft64(s.x0, -19) ^ bits.RotateLeft64(s.x0, -28)
	s.x1 ^= bits.RotateLeft64(s.x1, -61) ^ bits.RotateLeft64(s.x1, -39)
	s.x2 ^= bits.RotateLeft64(s.x2, -1) ^ bits.RotateLeft64(s.x2, -6)
	s.x3 ^= bits.RotateLeft64(s.x3, -10) ^ bits.RotateLeft64(s.x3, -17)
	s.x4 ^= bits.RotateLeft64(s.x4, -7) ^ bits.RotateLeft64(s.x4, -41)
	return s
}

func perm12(s state) state {
	s = round(0xf0, s)
	s = round(0xe1, s)
	s = round(0xd2, s)
	s = round(0xc3, s)
	s = round(0xb4, s)
	s = round(0xa5, s)
	s = round(0x96, s)
	s = round(0x87, s)
	s = round(0x78, s)
	s = round(0x69, s)
	s = round(0x5a, s)
	s = round(0x4b, s)
	return s
}

func perm6(s state) state {
	s = round(0x96, s)
	s = round(0x87, s)
	s = round(0x78, s)
	s = round(0x69, s)
	s = round(0x5a, s)
	s = round(0x4b, s)
	return s
}

// Function bigendianUint64 is similar to binary.BigEndian.Uint64,
// but allows partial or empty input.
func bigendianUint64(b []byte) uint64 {
	x := uint64(0)
	n := len(b)
	for i := 0; i < n; i++ {
		x |= uint64(b[i]) << (56 - 8*uint64(i))
	}
	return x
}

func bigendianPutUint64(b []byte, x uint64, n int) {
	for i := 0; i < n; i++ {
		b[i] = uint8(x >> (56 - 8*i))
	}
}

// Function chk is my non-standard way of testing error returns
// without cluttering the code, called in a non-gofmt manner.
// TODO Change to some idiomatic Go style, presumably more
// gracious with errors instead of log.Fatal everywhere. But don't
// be too gracious about cryptographically catastrophic choices.
func chk(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
