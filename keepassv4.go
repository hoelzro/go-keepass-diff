package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20"
)

const (
	VariantMapVersion      = 0x0100
	VariantMapCriticalMask = 0xff00

	VariantMapFieldTypeEnd       = 0
	VariantMapFieldTypeUint32    = 0x04
	VariantMapFieldTypeUint64    = 0x05
	VariantMapFieldTypeBool      = 0x08
	VariantMapFieldTypeInt32     = 0x0c
	VariantMapFieldTypeInt64     = 0x0d
	VariantMapFieldTypeString    = 0x18
	VariantMapFieldTypeByteArray = 0x42

	InnerHeaderFieldIDEnd       = 0
	InnerHeaderFieldIDStreamID  = 1
	InnerHeaderFieldIDStreamKey = 2
	InnerHeaderFieldIDBinary    = 3
)

type keepassV4Decryptor struct{}

func readVariantMap(data []byte) (map[string]any, error) {
	var version uint16

	r := bytes.NewReader(data)
	// XXX length checks/error checks
	binary.Read(r, binary.LittleEndian, &version)
	version &= VariantMapCriticalMask

	maxVersion := uint16(VariantMapVersion & VariantMapCriticalMask)
	if version > maxVersion {
		return nil, errors.New("unsupported variant map version")
	}

	result := make(map[string]any)

	for {
		var fieldType uint8
		var nameLen uint32
		var valueLen uint32

		// XXX length checks/error checks
		binary.Read(r, binary.LittleEndian, &fieldType)

		if fieldType == VariantMapFieldTypeEnd {
			return result, nil
		}

		binary.Read(r, binary.LittleEndian, &nameLen)
		nameBytes := make([]byte, nameLen)
		r.Read(nameBytes)
		binary.Read(r, binary.LittleEndian, &valueLen)
		valueBytes := make([]byte, valueLen)
		r.Read(valueBytes)

		name := string(nameBytes)

		switch fieldType {
		case VariantMapFieldTypeUint32:
			result[name] = binary.LittleEndian.Uint32(valueBytes)
		case VariantMapFieldTypeUint64:
			result[name] = binary.LittleEndian.Uint64(valueBytes)
		case VariantMapFieldTypeBool:
			result[name] = valueBytes[0] != 0
		case VariantMapFieldTypeInt32:
			var value int32
			binary.Read(bytes.NewReader(valueBytes), binary.LittleEndian, &value)
			result[name] = value
		case VariantMapFieldTypeInt64:
			var value int64
			binary.Read(bytes.NewReader(valueBytes), binary.LittleEndian, &value)
			result[name] = value
		case VariantMapFieldTypeString:
			result[name] = string(valueBytes)
		case VariantMapFieldTypeByteArray:
			result[name] = valueBytes
		default:
			return nil, errors.New("unknown field type in variant map")
		}
	}
}

func checkV4Validity(r io.Reader, signatureAndHeader []byte, masterKey, hmacKey []byte) error {
	headerSha256 := make([]byte, 32)
	_, err := r.Read(headerSha256)
	if err != nil {
		return err
	}
	gotHeaderSha256 := sha256.Sum256(signatureAndHeader)

	if !bytes.Equal(gotHeaderSha256[:], headerSha256) {
		return errors.New("header checksum mismatch")
	}

	headerHmac := make([]byte, 32)
	// XXX use io.ReadFull
	_, err = r.Read(headerHmac)
	if err != nil {
		return err
	}

	transform := sha512.New()
	transform.Write([]byte{
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	})
	transform.Write(hmacKey)
	trueKey := transform.Sum(nil)

	h := hmac.New(sha256.New, trueKey)
	h.Write(signatureAndHeader)
	gotHeaderHmac := h.Sum(nil)

	if !hmac.Equal(gotHeaderHmac, headerHmac) {
		return errors.New("header HMAC mismatch")
	}

	return nil
}

func readV4Blocks(r io.Reader, hmacKey []byte) ([]byte, error) {
	blockBytes := bytes.NewBuffer([]byte{})

	for blockIndex := uint64(0); ; blockIndex++ {
		blockHMAC := make([]byte, 32)
		_, err := r.Read(blockHMAC)
		if err != nil {
			return nil, err
		}
		var blockSize int32
		err = binary.Read(r, binary.LittleEndian, &blockSize)
		if err != nil {
			return nil, err
		}

		blockData := make([]byte, blockSize)
		if blockSize > 0 { // XXX my old code didn't have this?
			_, err = r.Read(blockData)
			if err != nil {
				return nil, err
			}
		}

		transform := sha512.New()
		binary.Write(transform, binary.LittleEndian, blockIndex)
		transform.Write(hmacKey)
		currentHMACKey := transform.Sum(nil)

		h := hmac.New(sha256.New, currentHMACKey)
		binary.Write(h, binary.LittleEndian, blockIndex)
		binary.Write(h, binary.LittleEndian, blockSize)
		h.Write(blockData)

		if !hmac.Equal(h.Sum(nil), blockHMAC) {
			return nil, errors.New("block HMAC mismatch")
		}

		blockBytes.Write(blockData)

		if blockSize == 0 {
			break
		}
	}

	return blockBytes.Bytes(), nil
}

func readV4InnerHeaders(r io.Reader) ([]byte, error) {
	var streamKey []byte

innerHeaderLoop:
	for {
		var fieldID uint8

		err := binary.Read(r, binary.LittleEndian, &fieldID)
		if err != nil {
			return nil, err
		}

		var fieldLength uint32
		err = binary.Read(r, binary.LittleEndian, &fieldLength)
		if err != nil {
			return nil, err
		}

		fieldData := make([]byte, fieldLength)
		err = binary.Read(r, binary.LittleEndian, fieldData)
		if err != nil {
			return nil, err
		}

		switch fieldID {
		case InnerHeaderFieldIDEnd:
			break innerHeaderLoop
		case InnerHeaderFieldIDStreamID:
			streamID := binary.LittleEndian.Uint32(fieldData)
			if streamID != StreamAlgorithmChaCha20 {
				return nil, errors.New("ChaCha20 required for KDBX4")
			}
		case InnerHeaderFieldIDStreamKey:
			streamKey = fieldData
		case InnerHeaderFieldIDBinary:
			return nil, errors.New("inner header field binary not yet implemented")
		}
	}

	if streamKey == nil {
		return nil, errors.New("No stream key found in inner headers")
	}

	return streamKey, nil
}

// XXX this is nearly identical to keepassV3Decryptor.readDatabaseHeader :(
func (v4 *keepassV4Decryptor) readDatabaseHeader(r io.Reader) (*keepassDatabaseHeader, error) {
	var masterSeed []byte
	var encryptionIV []byte
	var kdfParameters map[string]any

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

		var fieldLength uint32
		// XXX length checks?
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
		case EncryptionIV:
			encryptionIV = fieldData
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

	// XXX assert the KDF UUID is not argon2
	// kdfUUID := kdfParameters["$UUID"].([]byte)

	if masterSeed == nil {
		return nil, errors.New("master seed field not found")
	}
	if encryptionIV == nil {
		return nil, errors.New("encryption IV field not found")
	}

	// XXX also check for presence for better error message?
	transformSeed, ok := kdfParameters["S"].([]byte)
	if !ok {
		return nil, errors.New("transform seed was not a byte array")
	}

	rounds, ok := kdfParameters["R"].(uint64)
	if !ok {
		return nil, errors.New("transform rounds was not an integer")
	}

	return &keepassDatabaseHeader{
		masterSeed:    masterSeed,
		encryptionIV:  encryptionIV,
		transformSeed: transformSeed,
		rounds:        rounds,
	}, nil
}

func (v4 *keepassV4Decryptor) Decrypt(r io.Reader, password string) (*KeePassFile, error) {
	// At this point we've read the file signature from r, but we need it for the header integrity check
	// *Fortunately* the signature is two magic numbers and a version number that we know, so we don't
	// need to go out of our way to squirrel it away and pass it in
	signature := []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00, 0x00, 0x04, 0x00}
	headerBuffer := bytes.NewBuffer(signature)

	// …and then use a TeeReader to squirrel away the rest of the header's contents while reading it
	header, err := v4.readDatabaseHeader(io.TeeReader(r, headerBuffer))
	if err != nil {
		return nil, err
	}

	masterKey, err := makeMasterKey(header, password)
	if err != nil {
		return nil, err
	}

	var hmacKey []byte
	{
		transform := sha512.New()
		transform.Write(header.masterSeed)
		transform.Write(masterKey)
		transform.Write([]byte{0x01})
		hmacKey = transform.Sum(nil)
	}

	err = checkV4Validity(r, headerBuffer.Bytes(), masterKey, hmacKey)
	if err != nil {
		return nil, err
	}

	blockBytes, err := readV4Blocks(r, hmacKey)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(header.masterSeed)
	h.Write(masterKey)

	masterKey = h.Sum(nil)

	aesCipher, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	decrypt := cipher.NewCBCDecrypter(aesCipher, header.encryptionIV)
	plaintext := make([]byte, len(blockBytes))
	decrypt.CryptBlocks(plaintext, blockBytes)

	gzipReader, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}

	streamKey, err := readV4InnerHeaders(gzipReader)
	if err != nil {
		return nil, err
	}

	uncompressedPayload, err := io.ReadAll(gzipReader)
	// because the gzip'd XML is encrypted using a block cipher, it had to be padded up to the cipher's
	// block size - so there might be extra junk after the full gzip'd contents, which surfaces as a
	// gzip.ErrHeader.  It would be great to detect how *much* junk there is and be more precise in our
	// handling, but for now just ignore gzip.ErrHeader and rely on XML parsing to catch "real" gzip
	// errors
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, gzip.ErrHeader) {
		return nil, err
	}

	actualStreamKey := sha512.Sum512(streamKey)
	chachaStream, err := chacha20.NewUnauthenticatedCipher(actualStreamKey[:32], actualStreamKey[32:32+12])
	if err != nil {
		return nil, err
	}

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

	err = xml.Unmarshal(uncompressedPayload, &unmarshalMe)
	if err != nil {
		return nil, err
	}

	// XXX move this part into common code
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
	chachaStream.XORKeyStream(decryptedProtectedBytes, protectedBytes)

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
	rootGroup := unmarshalMe.Root.Groups.KeePassGroup

	result := &KeePassFile{}
	result.Root.Group = *rootGroup
	return result, nil
}
