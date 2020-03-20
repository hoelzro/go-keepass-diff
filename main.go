// XXX GPL header

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

type entry struct {
	name             string
	username         string
	notes            string
	password         string
	modificationTime time.Time
}

const SecondsBetweenEpochAndYearZero = int64(-62135596800)

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
		var lastModificationTime time.Time

		lastModificationBytes, err := base64.StdEncoding.DecodeString(e.Times.LastModificationTime)
		if err == nil {
			var lastModificationSeconds uint64
			err = binary.Read(bytes.NewReader(lastModificationBytes), binary.LittleEndian, &lastModificationSeconds)

			if err != nil {
				return err
			}

			lastModificationTime = time.Unix(int64(lastModificationSeconds)+SecondsBetweenEpochAndYearZero, 0)
		} else {
			lastModificationTime, err = time.Parse("2006-01-02T15:04:05Z", e.Times.LastModificationTime)
		}

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
