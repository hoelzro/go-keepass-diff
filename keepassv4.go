package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
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
	err := binary.Read(r, binary.LittleEndian, &version)
	if err != nil {
		return nil, err
	}
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
		err := binary.Read(r, binary.LittleEndian, &fieldType)
		if err != nil {
			return nil, err
		}

		if fieldType == VariantMapFieldTypeEnd {
			return result, nil
		}

		err = binary.Read(r, binary.LittleEndian, &nameLen)
		if err != nil {
			return nil, err
		}

		nameBytes := make([]byte, nameLen)
		_, err = io.ReadFull(r, nameBytes)
		if err != nil {
			return nil, err
		}

		err = binary.Read(r, binary.LittleEndian, &valueLen)
		if err != nil {
			return nil, err
		}

		valueBytes := make([]byte, valueLen)
		_, err = io.ReadFull(r, valueBytes)
		if err != nil {
			return nil, err
		}

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
			err := binary.Read(bytes.NewReader(valueBytes), binary.LittleEndian, &value)
			if err != nil {
				return nil, err
			}
			result[name] = value
		case VariantMapFieldTypeInt64:
			var value int64
			err := binary.Read(bytes.NewReader(valueBytes), binary.LittleEndian, &value)
			if err != nil {
				return nil, err
			}
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
	_, err := io.ReadFull(r, headerSha256)
	if err != nil {
		return err
	}
	gotHeaderSha256 := sha256.Sum256(signatureAndHeader)

	if !bytes.Equal(gotHeaderSha256[:], headerSha256) {
		return errors.New("header checksum mismatch")
	}

	headerHmac := make([]byte, 32)
	_, err = io.ReadFull(r, headerHmac)
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
		_, err := io.ReadFull(r, blockHMAC)
		if err != nil {
			return nil, err
		}
		var blockSize int32
		err = binary.Read(r, binary.LittleEndian, &blockSize)
		if err != nil {
			return nil, err
		}

		blockData := make([]byte, blockSize)
		_, err = io.ReadFull(r, blockData)
		if err != nil {
			return nil, err
		}

		transform := sha512.New()
		_ = binary.Write(transform, binary.LittleEndian, blockIndex)
		transform.Write(hmacKey)
		currentHMACKey := transform.Sum(nil)

		h := hmac.New(sha256.New, currentHMACKey)
		_ = binary.Write(h, binary.LittleEndian, blockIndex)
		_ = binary.Write(h, binary.LittleEndian, blockSize)
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

func (v4 *keepassV4Decryptor) Decrypt(r io.Reader, password string) (*KeePassFile, error) {
	// copy the magic numbers and version for integrity checks
	headerBuffer := bytes.NewBuffer(nil)
	_, err := io.CopyN(headerBuffer, r, 12)
	if err != nil {
		return nil, err
	}

	// read the header, and use a TeeReader to squirrel away the rest of the header's contents while
	// doing that so we have them for integrity checks
	header, err := readDatabaseHeader[uint32](io.TeeReader(r, headerBuffer))
	if err != nil {
		return nil, err
	}

	masterKey := header.kdf.MakeKey(password)

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

	// since AES is block-based, the gzip'd contents needs to be padded up to AES block size - which
	// leaves some "junk bytes" after the actual gzip'd bytes.  KeePass appears to pad the contents
	// with N bytes, where N is between 1-blockSize (so it'll even pad with blockSize bytes if it
	// doesn't have to pad at all), and the padding is the byte N repeated N times.  That means the
	// last byte contains the number of padding bytes that were added, so chop that off before
	// feeding it to gzip
	plaintext = plaintext[:len(plaintext)-int(plaintext[len(plaintext)-1])]

	gzipReader, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}

	streamKey, err := readV4InnerHeaders(gzipReader)
	if err != nil {
		return nil, err
	}

	uncompressedPayload, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	actualStreamKey := sha512.Sum512(streamKey)
	chachaStream, err := chacha20.NewUnauthenticatedCipher(actualStreamKey[:32], actualStreamKey[32:32+12])
	if err != nil {
		return nil, err
	}

	rootGroup, err := unmarshalAndDecryptProtectedValues(uncompressedPayload, chachaStream)
	if err != nil {
		return nil, err
	}

	result := &KeePassFile{}
	result.Root.Group = *rootGroup

	return result, nil
}
