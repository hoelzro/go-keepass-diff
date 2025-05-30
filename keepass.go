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
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/salsa20"
)

const (
	Signature1              = 0x9AA2D903
	Signature2              = 0xB54BFB67
	FileVersionCriticalMask = 0xFFFF0000
	FileVersion3            = 0x00030000
	FileVersion4            = 0x00040000

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
	KdfParameters       = 11
	PublicCustomData    = 12 // nolint:deadcode

	CompressionAlgorithmGzip = 1

	StreamAlgorithmArcFourVariant = 1 // nolint:deadcode
	StreamAlgorithmSalsa20        = 2
	StreamAlgorithmChaCha20       = 3

	SecondsBetweenEpochAndYearZero = int64(-62135596800)
)

var (
	KdfUUIDAes      = uuid.Must(uuid.Parse("c9d9f39a-628a-4460-bf74-0d08c18a4fea"))
	KdfUUIDArgon2id = uuid.Must(uuid.Parse("9e298b19-56db-4773-b23d-fc3ec6f0a1e6"))
)

var CipherAES256 []byte = []byte{0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff}

var KeepassIV []byte = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}

type KeePassTimes struct {
	LastModificationTime time.Time
	Expires              bool
	ExpiryTime           time.Time
}

func (times *KeePassTimes) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var unmarshalTimes struct {
		LastModificationTime string
		Expires              bool
		ExpiryTime           string
	}

	err := d.DecodeElement(&unmarshalTimes, &start)
	if err != nil {
		return err
	}

	var lastModificationTime time.Time
	if lastModificationTimeBytes, err := base64.StdEncoding.DecodeString(unmarshalTimes.LastModificationTime); err == nil {
		// try base-64 encoded time…
		lastModificationTime = time.Unix(int64(binary.LittleEndian.Uint64(lastModificationTimeBytes))+SecondsBetweenEpochAndYearZero, 0)
	} else {
		// … fall back to time as-is
		lastModificationTime, err = time.Parse("2006-01-02T15:04:05Z", unmarshalTimes.LastModificationTime)
		if err != nil {
			return err
		}
	}

	var expiryTime time.Time
	if expiryTimeBytes, err := base64.StdEncoding.DecodeString(unmarshalTimes.ExpiryTime); err == nil {
		// try base-64 encoded time…
		expiryTime = time.Unix(int64(binary.LittleEndian.Uint64(expiryTimeBytes))+SecondsBetweenEpochAndYearZero, 0)
	} else {
		// … fall back to time as-is
		expiryTime, err = time.Parse("2006-01-02T15:04:05Z", unmarshalTimes.ExpiryTime)
		if err != nil {
			return err
		}
	}

	times.LastModificationTime = lastModificationTime
	times.Expires = unmarshalTimes.Expires
	times.ExpiryTime = expiryTime

	return nil
}

// XXX lower case struct name for privacy?
//
//	demarshal modification times/history/recycle bin for easier merging?
type KeePassEntry struct {
	Times     KeePassTimes
	KeyValues map[string]string // XXX member name?
	History   []KeePassEntry
	Tags      string
}

type KeePassGroup struct {
	Name    string         `xml:"Name"`
	Notes   string         `xml:"Notes"`
	Groups  []KeePassGroup `xml:"Group"`
	Entries []KeePassEntry `xml:"Entry"`
}

type KeePassFile struct {
	Root struct {
		Group KeePassGroup `xml:"Group"`
	} `xml:"Root"`
}

func checkMagicSignature(r io.Reader) (keepassDecryptor, error) {
	var magic struct {
		Signature1 uint32
		Signature2 uint32
		Version    uint32
	}

	err := binary.Read(r, binary.LittleEndian, &magic)
	if err != nil {
		return nil, err
	}

	if magic.Signature1 != Signature1 {
		return nil, errors.New("signature mismatch")
	}

	if magic.Signature2 != Signature2 {
		return nil, errors.New("signature mismatch")
	}

	magic.Version &= FileVersionCriticalMask

	switch magic.Version {
	case FileVersion3:
		return &keepassV3Decryptor{}, nil
	case FileVersion4:
		return &keepassV4Decryptor{}, nil
	default:
		return nil, errors.New("version mismatch")
	}
}

type KeyDerivationFunction interface {
	MakeKey(password string) []byte
}

type keepassDatabaseHeader struct {
	masterSeed         []byte
	encryptionIV       []byte
	protectedStreamKey []byte
	streamStartBytes   []byte

	kdf KeyDerivationFunction
}

type aesKDF struct {
	aesCipher cipher.Block
	rounds    uint64
}

func (kdf *aesKDF) MakeKey(password string) []byte {
	passwordHash := sha256.Sum256([]byte(password))

	compositeKey := sha256.Sum256(passwordHash[:])

	transformedKey := compositeKey
	aesCipher := kdf.aesCipher
	// XXX multithread this using a stretched out slice
	for i := uint64(0); i < kdf.rounds; i++ {
		aesCipher.Encrypt(transformedKey[0:16], transformedKey[0:16])
		aesCipher.Encrypt(transformedKey[16:32], transformedKey[16:32])
	}
	transformedKey = sha256.Sum256(transformedKey[:])
	return transformedKey[:]
}

type argon2idKDF struct {
	seed        []byte
	rounds      uint32
	memory      uint32
	parallelism uint8
}

func (kdf *argon2idKDF) MakeKey(password string) []byte {
	passwordHash := sha256.Sum256([]byte(password))
	compositeKey := sha256.Sum256(passwordHash[:])

	return argon2.IDKey(compositeKey[:], kdf.seed, kdf.rounds, kdf.memory, kdf.parallelism, 32)
}

func createKDF(kdfParameters map[string]any) (KeyDerivationFunction, error) {
	kdfUUIDBytes := kdfParameters["$UUID"].([]byte)
	kdfUUID, err := uuid.FromBytes(kdfUUIDBytes)
	if err != nil {
		return nil, err
	}

	if kdfUUID == KdfUUIDAes {
		// XXX also check for presence for better error message?
		transformSeed, ok := kdfParameters["S"].([]byte)
		if !ok {
			return nil, errors.New("transform seed was not a byte array")
		}

		rounds, ok := kdfParameters["R"].(uint64)
		if !ok {
			return nil, errors.New("transform rounds was not an integer")
		}

		aesCipher, err := aes.NewCipher(transformSeed)
		if err != nil {
			return nil, err
		}

		return &aesKDF{
			aesCipher: aesCipher,
			rounds:    rounds,
		}, nil
	} else if kdfUUID == KdfUUIDArgon2id {
		// XXX also check for presence for better error message?
		seed, ok := kdfParameters["S"].([]byte)
		if !ok {
			return nil, errors.New("seed was not a byte array")
		}

		rounds, ok := kdfParameters["I"].(uint64)
		if !ok {
			return nil, errors.New("transform rounds was not an integer")
		}

		memory, ok := kdfParameters["M"].(uint64)
		if !ok {
			return nil, errors.New("memory was not an integer")
		}

		parallelism, ok := kdfParameters["P"].(uint32)
		if !ok {
			return nil, errors.New("parallelism was not an integer")
		}

		if memory%1024 != 0 {
			return nil, errors.New("can't handle Argon2 memory parameter not divisible by 1024")
		}

		return &argon2idKDF{
			seed:        seed,
			memory:      uint32(memory / 1024),
			parallelism: uint8(parallelism),
			rounds:      uint32(rounds),
		}, nil
	} else {
		return nil, errors.New("unknown/unsupported KDF")
	}
}

func readDatabaseHeader[FieldLength uint16 | uint32](r io.Reader) (*keepassDatabaseHeader, error) {
	var masterSeed []byte
	var encryptionIV []byte
	var protectedStreamKey []byte
	var streamStartBytes []byte
	kdfParameters := make(map[string]any)

headerLoop:
	for {
		var fieldID uint8
		err := binary.Read(r, binary.LittleEndian, &fieldID)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}

		var fieldLength FieldLength
		err = binary.Read(r, binary.LittleEndian, &fieldLength)
		if err != nil {
			return nil, err
		}

		fieldData := make([]byte, fieldLength)
		_, err = io.ReadFull(r, fieldData)
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

			uuidBytes, err := KdfUUIDAes.MarshalBinary()
			if err != nil {
				return nil, err
			}
			kdfParameters["$UUID"] = uuidBytes
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
			kdfParameters["S"] = fieldData
		case TransformRounds:
			var rounds uint64
			err := binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, &rounds)
			if err != nil {
				return nil, err
			}
			kdfParameters["R"] = rounds
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
		case KdfParameters:
			var err error

			kdfParameters, err = readVariantMap(fieldData)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("invalid header field ID")
		}
	}

	if masterSeed == nil {
		return nil, errors.New("master seed field not found")
	}
	if encryptionIV == nil {
		return nil, errors.New("encryption IV field not found")
	}

	kdf, err := createKDF(kdfParameters)
	if err != nil {
		return nil, err
	}

	return &keepassDatabaseHeader{
		masterSeed:         masterSeed,
		encryptionIV:       encryptionIV,
		protectedStreamKey: protectedStreamKey,
		streamStartBytes:   streamStartBytes,

		kdf: kdf,
	}, nil
}

func checkFirstBlock(r io.Reader, header *keepassDatabaseHeader, decrypt cipher.BlockMode) error {
	firstCipherBlock := make([]byte, len(header.streamStartBytes))
	_, err := io.ReadFull(r, firstCipherBlock)
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

func unmarshalAndDecryptProtectedValues(uncompressedPayload []byte, cipherStream cipher.Stream) (*KeePassGroup, error) {
	// set up unmarshaling-specific data to thread a pointer to
	// this slice throughout the XML unmarshaling process
	var needsDecryption []protectedValueRef

	var unmarshalMe struct {
		Root struct {
			Groups *groupUnmarshaler `xml:"Group"`
		} `xml:"Root"`
	}
	unmarshalMe.Root.Groups = &groupUnmarshaler{
		needsDecryption: &needsDecryption,
	}

	err := xml.Unmarshal(uncompressedPayload, &unmarshalMe)
	if err != nil {
		return nil, err
	}

	// collect all of the bytes encrypted by the database stream cipher
	protectedBytes := make([]byte, 0)
	for _, ref := range needsDecryption {
		rawBytes, err := base64.StdEncoding.DecodeString(ref.m[ref.k])
		if err != nil {
			panic(err.Error())
		}
		protectedBytes = append(protectedBytes, rawBytes...)
	}

	// …decrypt those protected bytes
	decryptedProtectedBytes := make([]byte, len(protectedBytes))
	cipherStream.XORKeyStream(decryptedProtectedBytes, protectedBytes)

	// …and update the references with the decrypted strings
	for _, ref := range needsDecryption {
		rawBytes, err := base64.StdEncoding.DecodeString(ref.m[ref.k])
		if err != nil {
			panic(err.Error())
		}
		decryptedValue := decryptedProtectedBytes[:len(rawBytes)]
		decryptedProtectedBytes = decryptedProtectedBytes[len(rawBytes):]
		ref.m[ref.k] = string(decryptedValue)
	}

	// XXX assert there's exactly 1?
	return unmarshalMe.Root.Groups.KeePassGroup, nil
}

// z32 is run of 32 zero bytes
var z32 = make([]byte, 32)

type salsa20CipherStream struct {
	IV  []byte
	Key [32]byte
}

func (stream *salsa20CipherStream) XORKeyStream(dst, src []byte) {
	salsa20.XORKeyStream(dst, src, stream.IV, &stream.Key)
}

func decodeBlocks(r io.Reader, protectedStreamKey []byte) (*KeePassFile, error) {
	var result *KeePassFile

	for {
		var blockID uint32
		err := binary.Read(r, binary.LittleEndian, &blockID)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}

		blockHash := make([]byte, 32)
		_, err = io.ReadFull(r, blockHash)
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
		_, err = io.ReadFull(r, blockData)
		if err != nil {
			return nil, err
		}

		gzipReader, err := gzip.NewReader(bytes.NewReader(blockData))
		if err != nil {
			return nil, err
		}

		uncompressedPayload, err := io.ReadAll(gzipReader)
		if err != nil {
			return nil, err
		}

		rootGroup, err := unmarshalAndDecryptProtectedValues(uncompressedPayload, &salsa20CipherStream{
			IV:  KeepassIV,
			Key: sha256.Sum256(protectedStreamKey),
		})
		if err != nil {
			return nil, err
		}

		result = &KeePassFile{}
		result.Root.Group = *rootGroup
	}

	return result, nil
}

type keepassDecryptor interface {
	Decrypt(r io.Reader, password string) (*KeePassFile, error)
}

type keepassV3Decryptor struct{}

func (v3 *keepassV3Decryptor) Decrypt(r io.Reader, password string) (*KeePassFile, error) {
	// drop the magic numbers and version
	_, err := io.CopyN(io.Discard, r, 12)
	if err != nil {
		return nil, err
	}

	header, err := readDatabaseHeader[uint16](r)
	if err != nil {
		return nil, err
	}

	if header.protectedStreamKey == nil {
		return nil, errors.New("protected stream key field not found")
	}
	if header.streamStartBytes == nil {
		return nil, errors.New("stream start bytes field not found")
	}

	masterKey := header.kdf.MakeKey(password)

	h := sha256.New()
	h.Write(header.masterSeed)
	h.Write(masterKey)
	masterKey = h.Sum(nil)

	aesCipher, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	decrypt := cipher.NewCBCDecrypter(aesCipher, header.encryptionIV)

	err = checkFirstBlock(r, header, decrypt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	decrypt.CryptBlocks(plaintext, ciphertext)

	plaintextReader := bytes.NewReader(plaintext)

	return decodeBlocks(plaintextReader, header.protectedStreamKey)
}

func decryptDatabase(r io.Reader, password string) (*KeePassFile, error) {
	// read the magic numbers and version, but preserve the bytes so that we can pass them along,
	// because V4 integrity checks take them into account
	signatureBuffer := bytes.NewBuffer(nil)
	decryptor, err := checkMagicSignature(io.TeeReader(r, signatureBuffer))
	if err != nil {
		return nil, err
	}

	return decryptor.Decrypt(io.MultiReader(signatureBuffer, r), password)
}
