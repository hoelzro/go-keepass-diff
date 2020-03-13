// XXX GPL header

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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Signature1              = 0x9AA2D903
	Signature2              = 0xB54BFB67
	FileVersionCriticalMask = 0xFFFF0000
	FileVersion3            = 0x00030000

	EndOfHeader         = 0
	Comment             = 1
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
	PublicCustomData    = 12

	CompressionAlgorithmGzip = 1

	StreamAlgorithmArcFourVariant = 1
	StreamAlgorithmSalsa20        = 2
	StreamAlgorithmChaCha20       = 3
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
	cipherStream io.Reader

	Times     KeePassTimes
	KeyValues map[string]string // XXX member name?
}

func (entry *KeePassEntry) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if entry.KeyValues == nil {
		entry.KeyValues = make(map[string]string)
	}
	inHistory := false
	inHistoryEntry := false

	for {
		token, err := d.Token()
		if err != nil {
			return err
		}

		switch t := token.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "String":
				type keyValuePair struct {
					Key   string `xml:"Key"`
					Value struct {
						Value     string `xml:",chardata"`
						Protected bool   `xml:"Protected,attr"`
					} `xml:"Value"`
				}

				pair := keyValuePair{}
				err := d.DecodeElement(&pair, &t)
				if err != nil {
					return err
				}
				if pair.Value.Protected {
					rawBytes, err := base64.StdEncoding.DecodeString(pair.Value.Value)
					if err != nil {
						panic(err.Error())
					}
					cipherMaskBytes := make([]byte, len(rawBytes))
					_, _ = entry.cipherStream.Read(cipherMaskBytes)
					for i := range rawBytes {
						rawBytes[i] ^= cipherMaskBytes[i]
					}

					pair.Value.Value = string(rawBytes)
					pair.Value.Protected = false
				}
				if !inHistory {
					entry.KeyValues[pair.Key] = pair.Value.Value
				}
			case "Times":
				if !inHistory {
					err := d.DecodeElement(&entry.Times, &t)
					if err != nil {
						return err
					}
				}
			case "History":
				if inHistory {
					panic("you can't nest History")
				}
				inHistory = true
			case "Entry":
				if inHistory {
					if inHistoryEntry {
						panic("you can't nest History entries")
					}
					inHistoryEntry = true
				} else {
					panic("you can't nest Entry")
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Entry":
				if !inHistory {
					return nil
				}
				inHistoryEntry = false
			case "History":
				inHistory = false
			}
		}
	}
	return nil
}

type KeePassGroup struct {
	cipherStream io.Reader

	Name    string         `xml:"Name"`
	Notes   string         `xml:"Notes"`
	Groups  []KeePassGroup `xml:"Group"`
	Entries []KeePassEntry `xml:"Entry"`
}

func (group *KeePassGroup) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}

		switch t := token.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Name":
				err := d.DecodeElement(&group.Name, &t)
				if err != nil {
					return err
				}
			case "Notes":
				err := d.DecodeElement(&group.Notes, &t)
				if err != nil {
					return err
				}
			case "Group":
				subgroup := KeePassGroup{cipherStream: group.cipherStream}
				err := d.DecodeElement(&subgroup, &t)
				if err != nil {
					return err
				}
				group.Groups = append(group.Groups, subgroup)
			case "Entry":
				entry := KeePassEntry{cipherStream: group.cipherStream}
				err := d.DecodeElement(&entry, &t)
				if err != nil {
					return err
				}
				group.Entries = append(group.Entries, entry)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Group":
				return nil
			}
		}
	}

	return nil
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

type zeroReader struct{}

func (z *zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}

	return len(p), nil
}

func newZeroReader() io.Reader {
	return &zeroReader{}
}

func decodeBlocks(r io.Reader, protectedStreamKey []byte) (*KeePassFile, error) {
	var result *KeePassFile

	actualKey := sha256.Sum256(protectedStreamKey)
	cipherStream, err := NewSalsa20Reader(newZeroReader(), actualKey[:], KeepassIV)
	if err != nil {
		return nil, err
	}

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
			if !bytes.Equal(blockHash, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
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
		keepassFile.Root.Group.cipherStream = cipherStream

		err = xml.Unmarshal(uncompressedPayload, &keepassFile)
		if err != nil {
			return nil, err
		}

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

func dumpKeePassEntries(group *KeePassGroup, depth int) {
	fmt.Println(strings.Repeat("  ", depth) + group.Name)
	for _, child := range group.Groups {
		dumpKeePassEntries(&child, depth+1)
	}
	for _, entry := range group.Entries {
		name := entry.KeyValues["Title"]
		pw := entry.KeyValues["Password"]

		fmt.Println(strings.Repeat("  ", depth+1) + name + " " + pw)
	}
}

type entry struct {
	name             string
	username         string
	notes            string
	password         string
	modificationTime time.Time
}

func flattenGroupsHelper(group *KeePassGroup, groupMap map[string][]entry, prefix string) error {
	fullGroupName := prefix + group.Name

	for _, child := range group.Groups {
		err := flattenGroupsHelper(&child, groupMap, fullGroupName+"/")
		if err != nil {
			return err
		}
	}

	groupMap[fullGroupName] = make([]entry, 0, len(group.Entries))

	for _, e := range group.Entries {
		name := e.KeyValues["Title"]
		password := e.KeyValues["Password"]
		username := e.KeyValues["UserName"]
		notes := e.KeyValues["Notes"]

		// XXX do this parsing in the XML unmarshal?
		//     if you do, you can remove the error return type on this function
		lastModificationTime, err := time.Parse("2006-01-02T15:04:05Z", e.Times.LastModificationTime)
		if err != nil {
			return err
		}

		groupMap[fullGroupName] = append(groupMap[fullGroupName], entry{
			name:             name,
			username:         username,
			password:         password,
			notes:            notes,
			modificationTime: lastModificationTime,
		})
	}

	return nil
}

func flattenGroups(k *KeePassFile) (map[string][]entry, error) {
	groups := make(map[string][]entry)
	// XXX assert that len(k.Root.Group.Entries) == 0?
	for _, g := range k.Root.Group.Groups {
		if g.Name == "Backup" {
			continue
		}

		err := flattenGroupsHelper(&g, groups, "")
		if err != nil {
			return nil, err
		}
	}

	return groups, nil
}

// XXX don't prompt for PW if checksum is same
// XXX check if there are no differences but the checksum is not the same
func main() {
	runtime.GOMAXPROCS(4)

	if len(os.Args) < 3 {
		fmt.Printf("usage: %s [first KDBX file] [second KDBX file]\n", os.Args[0])
		os.Exit(1)
	}

	firstFilename := os.Args[1]
	secondFilename := os.Args[2]

	f1, err := os.Open(firstFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer f1.Close()

	f2, err := os.Open(secondFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	password, err := readPassword("Password for " + firstFilename + ": ")
	if err != nil {
		log.Fatal(err)
	}

	var dbOne *KeePassFile
	var errOne error

	var dbTwo *KeePassFile
	var errTwo error

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		dbOne, errOne = decryptDatabase(f1, password)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		dbTwo, errTwo = decryptDatabase(f2, password)
		wg.Done()
	}()

	wg.Wait()

	if errOne != nil {
		log.Fatal(errOne)
	}

	if errTwo != nil {
		log.Fatal(errTwo)
	}

	// XXX detect entry rename/move to different group
	//     leverage history for ↑ (leverage history in general)
	oneGroups, err := flattenGroups(dbOne)
	if err != nil {
		log.Fatal(err)
	}
	twoGroups, err := flattenGroups(dbTwo)
	if err != nil {
		log.Fatal(err)
	}

	for groupName := range oneGroups {
		if _, present := twoGroups[groupName]; !present {
			fmt.Printf("Group %s exists in %s, but not %s\n", groupName, firstFilename, secondFilename)
		}
	}

	for groupName := range twoGroups {
		if _, present := oneGroups[groupName]; !present {
			fmt.Printf("Group %s exists in %s, but not %s\n", groupName, secondFilename, firstFilename)
		}
	}

	groupNames := make([]string, 0, len(oneGroups))

	for groupName := range oneGroups {
		groupNames = append(groupNames, groupName)
	}

	sort.Strings(groupNames)

	for _, groupName := range groupNames {
		oneGroupEntries := oneGroups[groupName]
		groupPrinted := false

		twoGroupEntries, present := twoGroups[groupName]
		if !present {
			continue
		}

		oneEntriesByName := make(map[string]entry)
		twoEntriesByName := make(map[string]entry)

		names := []string{}

		for _, entry := range oneGroupEntries {
			oneEntriesByName[entry.name] = entry

			names = append(names, entry.name)
		}

		for _, entry := range twoGroupEntries {
			twoEntriesByName[entry.name] = entry

			if _, present := oneEntriesByName[entry.name]; !present {
				names = append(names, entry.name)
			}
		}

		sort.Strings(names)

		for _, name := range names {
			entryOne, presentOne := oneEntriesByName[name]
			entryTwo, presentTwo := twoEntriesByName[name]

			msg := ""

			var newer string

			if presentOne && presentTwo {
				if entryOne.modificationTime.After(entryTwo.modificationTime) {
					newer = firstFilename
				} else {
					newer = secondFilename
				}
			}

			if presentOne && !presentTwo {
				msg = fmt.Sprintf("Entry '%s' exists in %s, but not %s", name, firstFilename, secondFilename)
			} else if presentTwo && !presentOne {
				msg = fmt.Sprintf("Entry '%s' exists in %s, but not %s", name, secondFilename, firstFilename)
			} else if entryOne.username != entryTwo.username {
				msg = fmt.Sprintf("Entry '%s' has two different usernames (%s is newer)", name, newer)
			} else if entryOne.password != entryTwo.password {
				msg = fmt.Sprintf("Entry '%s' has two different passwords (%s is newer)", name, newer)
			} else if entryOne.notes != entryTwo.notes {
				msg = fmt.Sprintf("Entry '%s' has two different notes (%s is newer)", name, newer)
			}

			if msg != "" {
				if !groupPrinted {
					fmt.Println(groupName)
					groupPrinted = true
				}
				fmt.Println("  " + msg)
			}
		}
	}
}
