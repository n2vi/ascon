// Copyright©2019 Eric Grosse n2vi.com/BSD2.txt

/*
Command paxz is like tar|gzip|openssl enc, but with long filenames and simple crypto.
Specifically, it writes to Stdout a POSIX.1-2001-format archive of the current working
directory, gzip-compressed and ASCON80pq-encrypted, ignoring special files.

"paxz -d dir" reads such an archive from Stdin, and recreates in a new subdirectory dir.
Symbolic links are not (yet) restored, out of security concerns yet to be analyzed.

The encryption key is supplied by environment variable P. As a quick check for mistyped
passphrases, paxz prints a checksum on Stderr. It is a matter of personal taste whether
passphrases should read from a raw mode terminal, from a file, from a command
line argument or from the environment as done here. None of the approaches is perfect.

I use this command for offline bulk backup; otherwise I prefer upspinfs or upsync.
The static linking and easy cross-compilation of Go makes this tool relatively painless
to use even on foreign systems.
*/
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"time"

	"github.com/n2vi/ascon/ascon80pq"
)

var ddir = flag.String("d", "", "new directory to unarchive into")

func main() {
	flag.Parse()
	if *ddir != "" {
		unarchive()
	} else {
		archive()
	}
}

func archive() {
	done := make(chan bool)
	piper, pipew := io.Pipe()
	go func() {
		encryptPAXZ(os.Stdout, piper)
		done <- true
	}()
	zw := gzip.NewWriter(pipew)
	tw := tar.NewWriter(zw)
	st, err := os.Lstat(".")
	chk(err)
	putfile(tw, ".", st)
	err = tw.Close()
	chk(err)
	err = zw.Close()
	chk(err)
	err = pipew.Close()
	chk(err)
	<-done
}

func putfile(tw *tar.Writer, pathname string, st os.FileInfo) {
	mode := st.Mode()
	hdr := &tar.Header{
		Name:    pathname,
		Mode:    int64(mode.Perm()),
		ModTime: st.ModTime(),
	}
	switch {
	case mode.IsRegular():
		hdr.Typeflag = tar.TypeReg
		hdr.Size = st.Size()
		err := tw.WriteHeader(hdr)
		chk(err)
		file, err := os.Open(st.Name())
		chk(err)
		n, err := io.Copy(tw, file)
		chk(err)
		err = file.Close()
		chk(err)
		if n != hdr.Size {
			log.Fatalf("size mismatch for %s: %d %d\n", hdr.Name, n, hdr.Size)
		}
	case mode&os.ModeSymlink != 0:
		hdr.Typeflag = tar.TypeSymlink
		linkname, err := os.Readlink(st.Name())
		chk(err)
		hdr.Linkname = linkname
		err = tw.WriteHeader(hdr)
		chk(err)
	case mode.IsDir():
		file, err := os.Open(st.Name())
		chk(err)
		defer file.Close()
		files, err := file.Readdir(0)
		chk(err)
		err = os.Chdir(st.Name())
		chk(err)
		for _, st := range files {
			newpath := pathname + "/" + st.Name()
			if pathname == "." {
				newpath = st.Name()
			}
			putfile(tw, newpath, st)
		}
		err = os.Chdir("..")
		chk(err)
	default:
		log.Printf("%s is not a normal file; skipping", st.Name())
	}

}

// Function encryptPAXZ wraps ascon80pq.Encrypt, picking a random nonce and
// descriptive associated data, generating a key from environment variable P, and
// writing ad || nonce || ciphertext || tag to the output stream.
// To later read the "associated data", use "sed 1q"; no key required.
func encryptPAXZ(ciphertext io.Writer, plaintext io.Reader) {
	passphrase := os.Getenv("P")
	if len(passphrase) < 8 {
		log.Fatalf("len(password)=%d suggests a catastrophic mistake", len(passphrase))
	}
	passsum := sha256.Sum256([]byte(passphrase))
	key := passsum[0:20]
	check := proquint((uint16(passsum[20]) << 8) | uint16(passsum[21]))
	fmt.Fprintf(os.Stderr, "paxz keysum %s\n", check)
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	chk(err)

	// Construct AD="paxz host `pwd` yyyy-mm-dd hh:mm:ss.ss\n".
	// Nonce should be unique anyway, but a unique AD provides a cryptographic safety net,
	// as well as providing some help identifying backup files.
	hostname, err := os.Hostname()
	chk(err)
	wd, err := os.Getwd()
	chk(err)
	timestamp := time.Now().UTC().String()[:22]
	ad := []byte("paxz " + hostname + " " + wd + " " + timestamp + "\n")
	_, err = ciphertext.Write(ad)
	chk(err)
	n, err := ciphertext.Write(nonce)
	chk(err)
	if n != len(nonce) {
		log.Fatal("partial write of nonce without err?")
	}
	ascon80pq.Encrypt(ciphertext, plaintext, ad, nonce, key)
}

func unarchive() {
	err := os.Mkdir(*ddir, 0700)
	chk(err)
	piper, pipew := io.Pipe()
	go func() {
		defer pipew.Close()
		err := decryptPAXZ(pipew, os.Stdin)
		if err != nil {
			rmerr := os.RemoveAll(*ddir)
			if rmerr != nil {
				log.Print(rmerr)
			}
			log.Fatal(err)
		}
	}()
	zr, err := gzip.NewReader(piper)
	chk(err)
	tr := tar.NewReader(zr)
	getfile(tr)
	err = zr.Close()
	chk(err)
}

func getfile(tr *tar.Reader) {
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		chk(err)
		name := path.Clean("/"+h.Name)   // absolutize to prevent .. out of current directory
		dir := path.Dir(name)
		fi := h.FileInfo()
		if fi.IsDir() {
			err = os.MkdirAll(*ddir+name, 0700)
			chk(err)
		} else {
			err = os.MkdirAll(*ddir+dir, 0700)
			chk(err)
			f, err := os.OpenFile(*ddir+name, os.O_WRONLY|os.O_CREATE, 0600)
			chk(err)
			if fi.Mode().IsRegular() {
				_, err = io.Copy(f, tr)
				chk(err)
			} else if fi.Mode()&os.ModeSymlink != 0 {
				_, err = f.WriteString("symlink " + h.Linkname)
				chk(err)
				fmt.Fprintf(os.Stderr, "not restoring symlink %s\n", name[1:])
			}
			err = f.Close()
			chk(err)
		}
	}
}

// MissingAD is the error returned if decryptPAXZ is unable to begin parsing input.
var MissingAD = errors.New("unable to read paxz header")

// Function decryptPAXZ undoes encryptPAXZ.
func decryptPAXZ(plaintext io.Writer, ciphertext io.Reader) error {
	passphrase := os.Getenv("P")
	passsum := sha256.Sum256([]byte(passphrase))
	key := passsum[0:20]
	check := proquint((uint16(passsum[20]) << 8) | uint16(passsum[21]))
	fmt.Fprintf(os.Stderr, "paxz keysum %s\n", check)

	nextbyte := make([]byte, 1)
	ad := make([]byte, 0, 200)
	for {
		n, err := ciphertext.Read(nextbyte)
		chk(err)
		if err != nil || n < 1 {
			return MissingAD
		}
		ad = append(ad, nextbyte[0])
		if nextbyte[0] == byte('\n') {
			break
		}
		if len(ad) == 5 && !bytes.Equal(ad, []byte("paxz ")) {
			return MissingAD
		}
	}
	if len(ad) < 29 {
		return MissingAD
	}
	return ascon80pq.Decrypt(plaintext, ciphertext, ad, key)
}

// TODO switch to community-tolerable error handling
func chk(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// See http://arxiv.org/html/0901.4016 and upspin.io/key/proquint.
var (
	pqcons  = []byte("bdfghjklmnprstvz")
	pqvowel = []byte("aiou")
)

// Encode returns a five-letter word representing a uint16.
func proquint(x uint16) (s []byte) {
	cons3 := x & 0x0f
	x >>= 4
	vow2 := x & 0x03
	x >>= 2
	cons2 := x & 0x0f
	x >>= 4
	vow1 := x & 0x03
	x >>= 2
	cons1 := x & 0x0f
	s = make([]byte, 5)
	s[0] = pqcons[cons1]
	s[1] = pqvowel[vow1]
	s[2] = pqcons[cons2]
	s[3] = pqvowel[vow2]
	s[4] = pqcons[cons3]
	return
}
