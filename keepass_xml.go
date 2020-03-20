package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"time"
)

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

const SecondsBetweenEpochAndYearZero = int64(-62135596800)

func (t *KeePassTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var stringValue string
	err := d.DecodeElement(&stringValue, &start)
	if err != nil {
		return nil
	}

	var lastModificationTime time.Time

	lastModificationBytes, err := base64.StdEncoding.DecodeString(stringValue)
	if err == nil {
		var lastModificationSeconds uint64
		err = binary.Read(bytes.NewReader(lastModificationBytes), binary.LittleEndian, &lastModificationSeconds)

		if err != nil {
			return err
		}

		lastModificationTime = time.Unix(int64(lastModificationSeconds)+SecondsBetweenEpochAndYearZero, 0)
	} else {
		lastModificationTime, err = time.Parse("2006-01-02T15:04:05Z", stringValue)
	}

	if err != nil {
		return err
	}

	*t = KeePassTime(lastModificationTime)

	return nil
}
