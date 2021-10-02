package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/salsa20"
)

const (
	Signature1              = 0x9AA2D903
	Signature2              = 0xB54BFB67
	FileVersionCriticalMask = 0xFFFF0000
	FileVersion3            = 0x00030000

	EndOfHeader         = 0
	Comment             = 1 // nolint:deadcode
	CipherID            = 2
	CompressionFlags    = 3
	MasterSeed          = 4
	TransformSeed       = 5
	TransformRounds     = 6
	EncryptionIV        = 7
	ProtectedStreamKey  = 8
	StreamStartBytes    = 9
	InnerRandomStreamID = 10
	KdfParameters       = 11 // nolint:deadcode
	PublicCustomData    = 12 // nolint:deadcode

	CompressionAlgorithmGzip = 1

	StreamAlgorithmArcFourVariant = 1 // nolint:deadcode
	StreamAlgorithmSalsa20        = 2
	StreamAlgorithmChaCha20       = 3 // nolint:deadcode
)

var CipherAES256 []byte = []byte{0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff}

var KeepassIV []byte = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}

type KeePassTimes struct {
	// XXX you could make a new type for this and impl UnmarshalXML for that type
	LastModificationTime string `xml:"LastModificationTime"`
}

// XXX lower case struct name for privacy?
//     demarshal modification times/history/recycle bin for easier merging?
type KeePassEntry struct {
	Times KeePassTimes
	// RawKeyValues get cleared by DecryptPassword
	RawKeyValues []struct {
		Key   string `xml:"Key"`
		Value struct {
			Value     string `xml:",chardata"`
			Protected bool   `xml:"Protected,attr"`
		} `xml:"Value"`
	} `xml:"String"`
	// KeyValues get populated by DecryptPassword
	KeyValues map[string]string // XXX member name?
}

func (e *KeePassEntry) DecryptPassword(key [32]byte) {
	e.KeyValues = make(map[string]string, len(e.RawKeyValues))
	for _, v := range e.RawKeyValues {
		if v.Value.Protected {
			rawBytes, err := base64.StdEncoding.DecodeString(v.Value.Value)
			if err != nil {
				panic(err.Error())
			}
			salsa20.XORKeyStream(rawBytes, rawBytes, KeepassIV, &key)
			e.KeyValues[v.Key] = string(rawBytes)
			continue
		}

		e.KeyValues[v.Key] = v.Value.Value
	}
	e.RawKeyValues = nil
}

type KeePassGroup struct {
	Name    string         `xml:"Name"`
	Notes   string         `xml:"Notes"`
	Groups  []KeePassGroup `xml:"Group"`
	Entries []KeePassEntry `xml:"Entry"`
}

func (g KeePassGroup) DecryptPasswords(key [32]byte) {
	for i := range g.Groups {
		g.Groups[i].DecryptPasswords(key)
	}

	for i := range g.Entries {
		g.Entries[i].DecryptPassword(key)
	}
}

type KeePassFile struct {
	Root struct {
		Group KeePassGroup `xml:"Group"`
	} `xml:"Root"`
}

func checkMagicSignature(r io.Reader) error {
	var magic struct {
		Signature1 uint32
		Signature2 uint32
		Version    uint32
	}

	err := binary.Read(r, binary.LittleEndian, &magic)
	if err != nil {
		return err
	}

	if magic.Signature1 != Signature1 {
		return errors.New("signature mismatch")
	}

	if magic.Signature2 != Signature2 {
		return errors.New("signature mismatch")
	}

	magic.Version &= FileVersionCriticalMask

	if magic.Version != FileVersion3 {
		return errors.New("version mismatch")
	}

	return nil
}

type keepassDatabaseHeader struct {
	masterSeed         []byte
	transformSeed      []byte
	encryptionIV       []byte
	protectedStreamKey []byte
	streamStartBytes   []byte
	rounds             uint64
}

func readDatabaseHeader(r io.Reader) (*keepassDatabaseHeader, error) {
	var masterSeed []byte
	var transformSeed []byte
	var encryptionIV []byte
	var protectedStreamKey []byte
	var streamStartBytes []byte
	var rounds *uint64

headerLoop:
	for {
		var fieldID uint8
		// XXX length checks?
		err := binary.Read(r, binary.LittleEndian, &fieldID)
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		var fieldLength uint16
		// XXX length checks?
		err = binary.Read(r, binary.LittleEndian, &fieldLength)
		if err != nil {
			return nil, err
		}

		fieldData := make([]byte, fieldLength)
		_, err = r.Read(fieldData)
		// XXX length checks?
		if err != nil {
			return nil, err
		}

		switch fieldID {
		case EndOfHeader:
			break headerLoop
		case CipherID:
			// if you extend this, you'll need to embed this information in
			// the keepassDatabaseHeader struct, you'll need to check that
			// that field's been set at the end of this function, and you'll
			// need to actually use the proper algorithm during seed transformation
			if !bytes.Equal(fieldData, CipherAES256) {
				return nil, errors.New("unsupported cipher")
			}
		case CompressionFlags:
			var compressionAlgorithm uint32
			err := binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, &compressionAlgorithm)
			if err != nil {
				return nil, err
			}
			// if you extend this, you'll need to embed this information in
			// the keepassDatabaseHeader struct, you'll need to check that
			// that field's been set at the end of this function, and you'll
			// need to actually use the proper algorithm during block data
			// reading
			if compressionAlgorithm != CompressionAlgorithmGzip {
				return nil, errors.New("unsupported compression algorithm")
			}
		case MasterSeed:
			if len(fieldData) != 32 {
				return nil, errors.New("insufficient field data")
			}
			masterSeed = fieldData
		case TransformSeed:
			if len(fieldData) != 32 {
				return nil, errors.New("insufficient field data")
			}
			transformSeed = fieldData
		case TransformRounds:
			rounds = new(uint64)
			err := binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, rounds)
			if err != nil {
				return nil, err
			}
		case EncryptionIV:
			encryptionIV = fieldData
		case ProtectedStreamKey:
			if len(fieldData) != 32 {
				return nil, errors.New("insufficient field data")
			}
			protectedStreamKey = fieldData
		case StreamStartBytes:
			if len(fieldData) != 32 {
				return nil, errors.New("insufficient field data")
			}
			streamStartBytes = fieldData
		case InnerRandomStreamID:
			var streamID uint32
			err := binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, &streamID)
			if err != nil {
				return nil, err
			}

			// if you extend this, you'll need to embed this information in
			// the keepassDatabaseHeader struct, you'll need to check that
			// that field's been set at the end of this function, and you'll
			// need to actually use the proper algorithm during key/value pair
			// reading
			if streamID != StreamAlgorithmSalsa20 {
				return nil, errors.New("unsupported stream algorithm")
			}
		default:
			return nil, errors.New("invalid header field ID")
		}
	}

	if masterSeed == nil {
		return nil, errors.New("master seed field not found")
	}
	if transformSeed == nil {
		return nil, errors.New("transform seed field not found")
	}
	if encryptionIV == nil {
		return nil, errors.New("encryption IV field not found")
	}
	if protectedStreamKey == nil {
		return nil, errors.New("protected stream key field not found")
	}
	if streamStartBytes == nil {
		return nil, errors.New("stream start bytes field not found")
	}
	if rounds == nil {
		return nil, errors.New("transform rounds field not found")
	}

	return &keepassDatabaseHeader{
		masterSeed:         masterSeed,
		transformSeed:      transformSeed,
		encryptionIV:       encryptionIV,
		protectedStreamKey: protectedStreamKey,
		streamStartBytes:   streamStartBytes,
		rounds:             *rounds,
	}, nil
}

func makeMasterKey(header *keepassDatabaseHeader, password string) ([]byte, error) {
	passwordHash := sha256.Sum256([]byte(password))

	compositeKey := sha256.Sum256(passwordHash[:])

	transformedKey := compositeKey
	aesCipher, err := aes.NewCipher(header.transformSeed)
	if err != nil {
		return nil, err
	}
	// XXX multithread this using a stretched out slice
	for i := uint64(0); i < header.rounds; i++ {
		aesCipher.Encrypt(transformedKey[0:16], transformedKey[0:16])
		aesCipher.Encrypt(transformedKey[16:32], transformedKey[16:32])
	}
	transformedKey = sha256.Sum256(transformedKey[:])

	h := sha256.New()
	h.Write(header.masterSeed)
	h.Write(transformedKey[:])
	return h.Sum(nil), nil
}

func checkFirstBlock(r io.Reader, header *keepassDatabaseHeader, decrypt cipher.BlockMode) error {
	firstCipherBlock := make([]byte, len(header.streamStartBytes))
	// XXX length check?
	_, err := r.Read(firstCipherBlock)
	if err != nil {
		return err
	}
	firstPlaintextBlock := make([]byte, len(header.streamStartBytes))
	decrypt.CryptBlocks(firstPlaintextBlock, firstCipherBlock)

	if !bytes.Equal(firstPlaintextBlock, header.streamStartBytes) {
		return errors.New("invalid password or corrupt database")
	}

	return nil
}

// z32 is run of 32 zero bytes
var z32 = make([]byte, 32)

func decodeBlocks(r io.Reader, protectedStreamKey []byte) (*KeePassFile, error) {
	var result *KeePassFile

	for {
		var blockID uint32
		err := binary.Read(r, binary.LittleEndian, &blockID)
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		blockHash := make([]byte, 32)
		// XXX is short read communicated as an error?
		_, err = r.Read(blockHash)
		if err != nil {
			return nil, err
		}

		var blockSize uint32
		err = binary.Read(r, binary.LittleEndian, &blockSize)
		if err != nil {
			return nil, err
		}

		if blockSize == 0 {
			if !bytes.Equal(blockHash, z32) {
				return nil, errors.New("invalid hash of final block")
			}
			break
		}

		blockData := make([]byte, blockSize)
		_, err = r.Read(blockData)
		if err != nil {
			return nil, err
		}

		gzipReader, err := gzip.NewReader(bytes.NewReader(blockData))
		if err != nil {
			return nil, err
		}

		uncompressedPayload, err := ioutil.ReadAll(gzipReader)
		if err != nil {
			return nil, err
		}

		keepassFile := KeePassFile{}

		err = xml.Unmarshal(uncompressedPayload, &keepassFile)
		if err != nil {
			return nil, err
		}

		keepassFile.Root.Group.DecryptPasswords(sha256.Sum256(protectedStreamKey))
		result = &keepassFile
	}

	return result, nil
}

func decryptDatabase(r io.Reader, password string) (*KeePassFile, error) {
	err := checkMagicSignature(r)
	if err != nil {
		return nil, err
	}

	header, err := readDatabaseHeader(r)
	if err != nil {
		return nil, err
	}

	masterKey, err := makeMasterKey(header, password)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	decrypt := cipher.NewCBCDecrypter(aesCipher, header.encryptionIV)

	err = checkFirstBlock(r, header, decrypt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	decrypt.CryptBlocks(plaintext, ciphertext)

	plaintextReader := bytes.NewReader(plaintext)

	return decodeBlocks(plaintextReader, header.protectedStreamKey)
}
