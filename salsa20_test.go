package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"testing"
)

var WhitespaceRegexp *regexp.Regexp = regexp.MustCompile(`\s+`)

// XXX inline the corpus (better yet, get the ESTREAM test vectors)
func TestCorpus(t *testing.T) {
	f, err := os.Open("salsa20-corpus")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	lineNumber := 1
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		pieces := WhitespaceRegexp.Split(line, -1)

		keyBytes, err := hex.DecodeString(pieces[0])
		if err != nil {
			log.Fatalln(err)
		}

		ivBytes, err := hex.DecodeString(pieces[1])
		if err != nil {
			log.Fatalln(err)
		}

		expectedPlaintextBytes, err := hex.DecodeString(pieces[2])
		if err != nil {
			log.Fatalln(err)
		}

		ciphertextBytes, err := hex.DecodeString(pieces[3])
		if err != nil {
			log.Fatalln(err)
		}

		decrypt, err := NewSalsa20Reader(bytes.NewReader(ciphertextBytes), keyBytes, ivBytes)
		if err != nil {
			log.Fatalln(err)
		}

		gotPlaintextBytes, _ := ioutil.ReadAll(decrypt)

		if !bytes.Equal(gotPlaintextBytes, expectedPlaintextBytes) {
			t.Fatalf("decryption mismatch on line %d\ngot      = %#v\nexpected = %#v", lineNumber, gotPlaintextBytes, expectedPlaintextBytes)
		}

		// XXX just do the block size test with a reader of 0s and compare it to a canonical stream using a big buffer?
		// XXX test with many block sizes? (non powers of 2, less than 64, =64, greater than 64, 63, 65, one +/- powers of 2 and mults of 64)
		decrypt, err = NewSalsa20Reader(bytes.NewReader(ciphertextBytes), keyBytes, ivBytes)
		buffer := make([]byte, 16)
		for offset := 0; offset < len(ciphertextBytes); offset += 16 {
			for i := range buffer {
				buffer[i] = 0
			}
			n, _ := decrypt.Read(buffer)
			if !bytes.Equal(buffer[:n], expectedPlaintextBytes[offset:offset+n]) {
				t.Fatalf("decryption mismatch on line %d (offset = %d)\ngot      = %#v\nexpected = %#v", lineNumber, offset, buffer[:n], expectedPlaintextBytes[offset:offset+n])
			}
		}

		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}
}

func TestDifferingBufferSize(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i + 1)
	}
	iv := make([]byte, 8)

	canonicalBlock := make([]byte, 1024)

	canonicalCipherStream, err := NewSalsa20Reader(newZeroReader(), key, iv)
	if err != nil {
		log.Fatalln(err)
	}

	canonicalCipherStream.Read(canonicalBlock)

	for bufferSize := 1; bufferSize <= 129; bufferSize++ {
		thisBlock := make([]byte, 1024)
		cipherStream, err := NewSalsa20Reader(newZeroReader(), key, iv)
		if err != nil {
			log.Fatalln(err)
		}

		for offset := 0; offset < 1024; offset += bufferSize {
			end := offset + bufferSize
			if end > len(thisBlock) {
				end = len(thisBlock)
			}
			cipherStream.Read(thisBlock[offset:end])
		}

		if !bytes.Equal(thisBlock, canonicalBlock) {
			t.Fatalf("Reading in chunks of %d didn't have the correct results", bufferSize)
		}
	}
}

func TestZeroBuffer(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i + 1)
	}
	iv := make([]byte, 8)

	streamWithZeroRead, err := NewSalsa20Reader(newZeroReader(), key, iv)
	if err != nil {
		log.Fatalln(err)
	}

	bufferWithZeroRead := make([]byte, 32)

	streamWithZeroRead.Read(bufferWithZeroRead[0:16])
	n, err := streamWithZeroRead.Read(make([]byte, 0))
	if err != nil {
		t.Fatal("Reading into a zero-length buffer should succeed")
	}
	if n != 0 {
		t.Fatal("Reading into a zero-length buffer should return 0 bytes read")
	}
	streamWithZeroRead.Read(bufferWithZeroRead[16:32])

	streamWithoutZeroRead, err := NewSalsa20Reader(newZeroReader(), key, iv)
	if err != nil {
		log.Fatalln(err)
	}

	bufferWithoutZeroRead := make([]byte, 32)
	streamWithoutZeroRead.Read(bufferWithoutZeroRead)

	if !bytes.Equal(bufferWithZeroRead, bufferWithoutZeroRead) {
		t.Fatal("Reading into a zero-length buffer shouldn't affect the state of the stream")
	}
}
