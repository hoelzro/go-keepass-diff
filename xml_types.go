package main

import (
	"encoding/xml"
)

// a reference to a value in a key/value pair that's been protected by the database
// stream cipher
type protectedValueRef struct {
	m map[string]string
	k string
}

// type for custom processing logic around key/value pairs
type keyValuesUnmarshaler struct {
	needsDecryption *[]protectedValueRef
	keyValues       map[string]string
}

func (attr *keyValuesUnmarshaler) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var kv struct {
		Key   string `xml:"Key"`
		Value struct {
			Value     string `xml:",chardata"`
			Protected bool   `xml:"Protected,attr"`
		} `xml:"Value"`
	}

	err := d.DecodeElement(&kv, &start)
	if err != nil {
		return err
	}

	attr.keyValues[kv.Key] = kv.Value.Value

	// if a value is marked as protected, it's been encrypted by the database stream
	// cipher and we need to add it to the list of values to be decrypted after we've
	// finished unmarshaling all of the XML
	if kv.Value.Protected {
		*attr.needsDecryption = append(*attr.needsDecryption, protectedValueRef{
			m: attr.keyValues,
			k: kv.Key,
		})
	}

	return nil
}

// type for custom processing logic around entries
// we use values of this type as a linked list so that we can pass a partially
// initialized value with the needsDecryption field set (otherwise, if we used a
// slice, we'd have no ability to control how values new to the slice are set up)
type entryUnmarshaler struct {
	*KeePassEntry

	// pointer to slice we're threading through to track which values need decryption
	needsDecryption *[]protectedValueRef
	previousEntry   *entryUnmarshaler
}

func (entry *entryUnmarshaler) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// squirrel away the current state in the next link in the chain so we can unmarshal
	// into the current entry but still retain the state of the previous entry we decoded
	entry.previousEntry = &entryUnmarshaler{
		KeePassEntry:    entry.KeePassEntry,
		needsDecryption: entry.needsDecryption,
		previousEntry:   entry.previousEntry,
	}

	var unmarshalMe struct {
		*KeePassEntry

		KeyValues keyValuesUnmarshaler `xml:"String"`

		History struct {
			Entries *entryUnmarshaler `xml:"Entry"`
		} `xml:"History"`
	}

	unmarshalMe.KeyValues = keyValuesUnmarshaler{
		needsDecryption: entry.needsDecryption,
		keyValues:       make(map[string]string),
	}

	unmarshalMe.History.Entries = &entryUnmarshaler{
		needsDecryption: entry.needsDecryption,
	}

	err := d.DecodeElement(&unmarshalMe, &start)
	if err != nil {
		return err
	}

	// extract the values we unmarshaled out of the XML
	entry.KeePassEntry = unmarshalMe.KeePassEntry
	entry.KeyValues = unmarshalMe.KeyValues.keyValues
	entry.History = make([]KeePassEntry, 0) // XXX better initial size?

	// walk the linked list we built up during unmarshaling and convert to a slice
	for ent := unmarshalMe.History.Entries; ent != nil; ent = ent.previousEntry {
		if ent.KeePassEntry != nil { // XXX I'd prefer to have the uninitialized one at the head and just discard it on iteration
			entry.History = append(entry.History, *ent.KeePassEntry)
		}
	}

	// since we were prepending to the linked list while unmarshaling, the entries
	// are in reverse order, so reverse the list
	for i := 0; i < len(entry.History)/2; i++ {
		entry.History[i], entry.History[len(entry.History)-1-i] = entry.History[len(entry.History)-1-i], entry.History[i]
	}

	return nil
}

// type for custom processing logic around groups
type groupUnmarshaler struct {
	*KeePassGroup

	needsDecryption *[]protectedValueRef
	previousGroup   *groupUnmarshaler
}

func (group *groupUnmarshaler) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// squirrel away the current state in the next link in the chain so we can unmarshal
	// into the current group but still retain the state of the previous group we decoded
	group.previousGroup = &groupUnmarshaler{
		KeePassGroup:    group.KeePassGroup,
		needsDecryption: group.needsDecryption,
		previousGroup:   group.previousGroup,
	}

	var unmarshalMe struct {
		*KeePassGroup

		Groups  *groupUnmarshaler `xml:"Group"`
		Entries *entryUnmarshaler `xml:"Entry"`
	}

	unmarshalMe.Groups = &groupUnmarshaler{
		needsDecryption: group.needsDecryption,
	}

	unmarshalMe.Entries = &entryUnmarshaler{
		needsDecryption: group.needsDecryption,
	}

	err := d.DecodeElement(&unmarshalMe, &start)
	if err != nil {
		return err
	}

	// extract the values we unmarshaled out of the XML
	group.KeePassGroup = unmarshalMe.KeePassGroup
	group.Groups = make([]KeePassGroup, 0) // XXX better initial size?

	// walk the linked list we built up during unmarshaling and convert to a slice
	for subgroup := unmarshalMe.Groups; subgroup != nil; subgroup = subgroup.previousGroup {
		if subgroup.KeePassGroup != nil { // XXX I'd prefer to have the uninitialized one at the head and just discard it on iteration
			group.Groups = append(group.Groups, *subgroup.KeePassGroup)
		}
	}

	// since we were prepending to the linked list while unmarshaling, the subgroups
	// are in reverse order, so reverse the list
	for i := 0; i < len(group.Groups)/2; i++ {
		group.Groups[i], group.Groups[len(group.Groups)-1-i] = group.Groups[len(group.Groups)-1-i], group.Groups[i]
	}

	group.Entries = make([]KeePassEntry, 0) // XXX better initial size?

	// walk the linked list we built up during unmarshaling and convert to a slice
	for ent := unmarshalMe.Entries; ent != nil; ent = ent.previousEntry {
		if ent.KeePassEntry != nil { // XXX I'd prefer to have the uninitialized one at the head and just discard it on iteration
			group.Entries = append(group.Entries, *ent.KeePassEntry)
		}
	}

	// since we were prepending to the linked list while unmarshaling, the entries
	// are in reverse order, so reverse the list
	for i := 0; i < len(group.Entries)/2; i++ {
		group.Entries[i], group.Entries[len(group.Entries)-1-i] = group.Entries[len(group.Entries)-1-i], group.Entries[i]
	}

	return nil
}
