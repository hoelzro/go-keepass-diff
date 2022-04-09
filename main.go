// XXX GPL header

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.org/x/term"
)

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

	fmt.Fprint(os.Stderr, "Password for "+firstFilename+": ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(os.Stderr, "\n")

	if err := diff(f1, f2, firstFilename, secondFilename, string(password), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func diff(f1, f2 io.Reader, firstFilename, secondFilename, password string, w io.Writer) error {
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
		return errOne
	}

	if errTwo != nil {
		return errTwo
	}

	// XXX detect entry rename/move to different group
	//     leverage history for ↑ (leverage history in general)
	oneGroups, err := flattenGroups(dbOne)
	if err != nil {
		return err
	}
	twoGroups, err := flattenGroups(dbTwo)
	if err != nil {
		return err
	}

	for groupName := range oneGroups {
		if _, present := twoGroups[groupName]; !present {
			fmt.Fprintf(w, "Group %s exists in %s, but not %s\n", groupName, firstFilename, secondFilename)
		}
	}

	for groupName := range twoGroups {
		if _, present := oneGroups[groupName]; !present {
			fmt.Fprintf(w, "Group %s exists in %s, but not %s\n", groupName, secondFilename, firstFilename)
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
			} else if !entryOne.modificationTime.Equal(entryTwo.modificationTime) {
				msg = fmt.Sprintf("Entry '%s' looks the same, but has two different modification times (%s is newer)", name, newer)
			}

			if msg != "" {
				if !groupPrinted {
					fmt.Fprintln(w, groupName)
					groupPrinted = true
				}
				fmt.Fprintln(w, "  "+msg)
			}
		}
	}

	return nil
}
