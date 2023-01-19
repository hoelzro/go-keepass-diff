// XXX GPL header

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/term"
)

var diffMode bool

func init() {
	flag.BoolVar(&diffMode, "diff", false, "show unified diff")
}

type entry struct {
	Attributes       map[string]string
	ModificationTime time.Time
}

func (e entry) name() string     { return e.Attributes["Title"] }
func (e entry) password() string { return e.Attributes["Password"] }
func (e entry) username() string { return e.Attributes["UserName"] }
func (e entry) notes() string    { return e.Attributes["Notes"] }
func (e entry) url() string      { return e.Attributes["URL"] }

func flattenGroupsHelper(group *KeePassGroup, groupMap map[string][]entry, path []string) error {
	path = append(path, group.Name)
	fullGroupName := strings.Join(path[1:], "/")

	for _, child := range group.Groups {
		// omit the Backup group at the top, if it exists (I think it might be
		// a holdover from earlier file formats)
		if len(path) == 1 && child.Name == "Backup" {
			continue
		}

		err := flattenGroupsHelper(&child, groupMap, path)
		if err != nil {
			return err
		}
	}

	groupMap[fullGroupName] = make([]entry, 0, len(group.Entries))

	for _, e := range group.Entries {
		// copy e.KeyValues so we can mutate them safely.
		attributes := make(map[string]string, len(e.KeyValues))
		for k, v := range e.KeyValues {
			attributes[k] = v
		}

		// XXX do this parsing in the XML unmarshal?
		//     if you do, you can remove the error return type on this function
		var lastModificationTime time.Time
		if lastModificationTimeBytes, err := base64.StdEncoding.DecodeString(e.Times.LastModificationTime); err == nil {
			// try base-64 encoded time…
			yearZero := time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
			lastModificationTime = time.Unix(int64(binary.LittleEndian.Uint64(lastModificationTimeBytes))+yearZero.Unix(), 0)
		} else {
			// … fall back to time as-is
			lastModificationTime, err = time.Parse("2006-01-02T15:04:05Z", e.Times.LastModificationTime)
			if err != nil {
				return err
			}
		}

		if diffMode {
			sum := sha256.New().Sum([]byte(attributes["Password"]))
			attributes["Password"] = fmt.Sprintf("sha256:%x", sum[:8])
		}

		groupMap[fullGroupName] = append(groupMap[fullGroupName], entry{
			Attributes:       attributes,
			ModificationTime: lastModificationTime,
		})
	}

	return nil
}

func flattenGroups(k *KeePassFile) (map[string][]entry, error) {
	groups := make(map[string][]entry)
	err := flattenGroupsHelper(&k.Root.Group, groups, make([]string, 0, 10))
	if err != nil {
		return nil, err
	}

	return groups, nil
}

// XXX don't prompt for PW if checksum is same
// XXX check if there are no differences but the checksum is not the same
func main() {
	runtime.GOMAXPROCS(4)

	flag.Parse()
	if len(flag.Args()) < 2 {
		fmt.Printf("usage: %s [first KDBX file] [second KDBX file]\n", os.Args[0])
		os.Exit(1)
	}

	firstFilename := flag.Arg(0)
	secondFilename := flag.Arg(1)

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

	if diffMode {
		if d := cmp.Diff(oneGroups, twoGroups); d != "" {
			fmt.Println("---", firstFilename)
			fmt.Println("+++", secondFilename)
			fmt.Print(d)
		}
	} else {
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
				oneEntriesByName[entry.name()] = entry

				names = append(names, entry.name())
			}

			for _, entry := range twoGroupEntries {
				twoEntriesByName[entry.name()] = entry

				if _, present := oneEntriesByName[entry.name()]; !present {
					names = append(names, entry.name())
				}
			}

			sort.Strings(names)

			for _, name := range names {
				entryOne, presentOne := oneEntriesByName[name]
				entryTwo, presentTwo := twoEntriesByName[name]

				msg := ""

				var newer string

				if presentOne && presentTwo {
					if entryOne.ModificationTime.After(entryTwo.ModificationTime) {
						newer = firstFilename
					} else {
						newer = secondFilename
					}
				}

				if presentOne && !presentTwo {
					msg = fmt.Sprintf("Entry '%s' exists in %s, but not %s", name, firstFilename, secondFilename)
				} else if presentTwo && !presentOne {
					msg = fmt.Sprintf("Entry '%s' exists in %s, but not %s", name, secondFilename, firstFilename)
				} else if entryOne.username() != entryTwo.username() {
					msg = fmt.Sprintf("Entry '%s' has two different usernames (%s is newer)", name, newer)
				} else if entryOne.url() != entryTwo.url() {
					msg = fmt.Sprintf("Entry '%s' has two different urls (%s is newer)", name, newer)
				} else if entryOne.password() != entryTwo.password() {
					msg = fmt.Sprintf("Entry '%s' has two different passwords (%s is newer)", name, newer)
				} else if entryOne.notes() != entryTwo.notes() {
					msg = fmt.Sprintf("Entry '%s' has two different notes (%s is newer)", name, newer)
				} else if !entryOne.ModificationTime.Equal(entryTwo.ModificationTime) {
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
	}

	return nil
}
