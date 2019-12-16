// Copyright©2019 Eric Grosse n2vi.com/BSD2.txt

package ascon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
	"testing"
)

// cipherWriter implements io.WriterCloser interface and prints diff between expected and actual ciphertext.
type cipherWriter struct {
	t        *testing.T
	adlen    int
	actual   []byte
	expected []byte
}

func (c *cipherWriter) Write(cipher []byte) (int, error) {
	c.actual = append(c.actual, cipher...)
	return len(cipher), nil
}

func (c *cipherWriter) Close() error {
	if bytes.Compare(c.actual, c.expected) != 0 {
		n := len(c.actual) - 16
		fmt.Printf("actual %02X %02X\n", c.actual[:n], c.actual[n:])
		n = len(c.expected) - 16
		fmt.Printf("expect %02X %02X\n", c.expected[:n], c.expected[n:])
		c.t.Errorf("mismatch")
	}
	return nil
}

func TestEncrypt(t *testing.T) {
	// Read test vectors published in github.com/ascon/ascon-c, which have the form:
	//
	// Count = 228
	// Key = 000102030405060708090A0B0C0D0E0F10111213
	// Nonce = 000102030405060708090A0B0C0D0E0F
	// PT = 000102030405
	// AD = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C
	// CT = 7D4DD96F7E3F5F1AFC786CF3465DF3D554D8EDD8EEC0

	var count int
	var key, nonce, plain, ad, cipher []byte
	katgz, err := os.Open("LWC_AEAD_KAT_160_128.txt.gz")
	chk(err)
	defer katgz.Close()
	kat, err := gzip.NewReader(katgz)
	chk(err)
	defer kat.Close()
	for scanner := bufio.NewScanner(kat); scanner.Scan(); {
		f := strings.Fields(scanner.Text())
		switch len(f) {
		case 0:
			continue
		case 2:
			// treat missing third field as empty string
			f = append(f, "")
		case 3:
			// normal case; proceed
		default:
			t.Errorf("unexpected input, number of fields = %d in %v", len(f), f)
		}
		if f[1] != "=" {
			t.Errorf("second field should have been = but was %s", f[1])
		}
		switch f[0] {
		case "Count":
			n, err := fmt.Sscanf(f[2], "%d", &count)
			chk(err)
			if n != 1 {
				t.Errorf("parse error for count %s", f[2])
			}
		case "Key":
			key = make([]byte, len(f[2])/2)
			n, err := fmt.Sscanf(f[2], "%X", &key)
			chk(err)
			if n != 1 {
				t.Errorf("parse error for key %s", f[2])
			}
		case "Nonce":
			nonce = make([]byte, len(f[2])/2)
			n, err := fmt.Sscanf(f[2], "%X", &nonce)
			chk(err)
			if n != 1 {
				t.Errorf("parse error for nonce %s", f[2])
			}
		case "PT":
			plain = make([]byte, len(f[2])/2)
			if len(plain) > 0 {
				n, err := fmt.Sscanf(f[2], "%X", &plain)
				chk(err)
				if n != 1 {
					t.Errorf("parse error for plain %s", f[2])
				}
			}
		case "AD":
			ad = make([]byte, len(f[2])/2)
			if len(ad) > 0 {
				n, err := fmt.Sscanf(f[2], "%X", &ad)
				chk(err)
				if n != 1 {
					t.Errorf("parse error for ad %s", f[2])
				}
			}
		case "CT":
			cipher = make([]byte, len(f[2])/2)
			n, err := fmt.Sscanf(f[2], "%X", &cipher)
			chk(err)
			if n != 1 {
				t.Errorf("parse error for cipher %s", f[2])
			}
			plaintext := bytes.NewReader(plain)
			ciphertext := &cipherWriter{
				t:        t,
				adlen:    len(ad),
				actual:   make([]byte, 0, 1000),
				expected: cipher,
			}
			Encrypt(ciphertext, plaintext, ad, nonce, key)
			ciphertext.Close()
		}
	}
}

// For detailed comparison, cf. ascon-c/tests/demo.c.
// func main() {
// 	key := make([]byte, 20)
// 	nonce := make([]byte, 16)
// 	encrypt(os.Stdout, strings.NewReader("ascon"), []byte("ASCON"), nonce, key)
// }
