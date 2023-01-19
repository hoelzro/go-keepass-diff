package main

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

//go:embed testdata/one.kdbx
var one []byte

//go:embed testdata/two.kdbx
var two []byte

var testdata fs.FS

//go:embed testdata
var _testdata embed.FS

func init() {
	var err error
	testdata, err = fs.Sub(_testdata, "testdata")
	if err != nil {
		panic("couldn't fs.Sub testdata:" + err.Error())
	}
}

type diffTest struct {
	left           string
	right          string
	expectedOutput string
}

var tests = []diffTest{
	{left: "one.kdbx", right: "two.kdbx", expectedOutput: "expected.txt"},
	// this file also tests that entries in the root group are diffed
	{left: "mod-time-only-before.kdbx", right: "mod-time-only-after.kdbx", expectedOutput: "mod-time-only-expected.txt"},
	{left: "onev4.kdbx", right: "twov4.kdbx", expectedOutput: "expected.txt"},
	// XXX one.kdbx and twov4.kdbx too
}

func TestDiff(t *testing.T) {
	for _, test := range tests {
		t.Run(fmt.Sprintf("comparing %s and %s", test.left, test.right), func(t *testing.T) {
			b := &bytes.Buffer{}

			leftFile, err := testdata.Open(test.left)
			if err != nil {
				t.Fatal(err)
			}

			defer leftFile.Close()

			rightFile, err := testdata.Open(test.right)
			if err != nil {
				t.Fatal(err)
			}

			defer rightFile.Close()

			if err := diff(
				leftFile,
				rightFile,
				"left.kdbx",
				"right.kdbx",
				"abc123",
				b,
			); err != nil {
				t.Fatal(err)
			}

			expected, err := fs.ReadFile(testdata, test.expectedOutput)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(string(expected), b.String()); diff != "" {
				t.Errorf("diff is wrong: %s", diff)
			}
		})
	}
}

var S string

func BenchmarkDiff(b *testing.B) {
	var s string
	for i := 0; i < b.N; i++ {
		b := &bytes.Buffer{}
		_ = diff(
			bytes.NewReader(one),
			bytes.NewReader(two),
			"one.kdbx",
			"two.kdbx",
			"abc123",
			b,
		)
		s = b.String()
	}
	S = s
}

func TestDecryptDatabase(t *testing.T) {
	f, err := decryptDatabase(bytes.NewReader(one), "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if c := len(f.Root.Group.Groups); c != 1 {
		t.Errorf("Expected group count of 1, got %d", c)
	}

	g := f.Root.Group.Groups[0]
	if c := len(g.Entries); c != 3 {
		t.Errorf("Expected entry count of 3, got %d", c)
	}

	kv := g.Entries[0].KeyValues
	if d := cmp.Diff("one", kv["Title"]); d != "" {
		t.Errorf("incorrect Title: %s", d)
	}
	if d := cmp.Diff("fUBH7WxV8O9sBhvh", kv["Password"]); d != "" {
		t.Errorf("incorrect Password: %s", d)
	}
}

func TestLoad(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".kdbx") {
			continue
		}

		// XXX subtest?
		path := path.Join("testdata", entry.Name())

		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
			continue
		}
		_, err = decryptDatabase(f, "abc123")
		f.Close()
		if err != nil {
			t.Errorf("failed to decrypt database %s: %v", path, err)
		}
	}
}

func findEntry(db *KeePassGroup, targetTitle string) *KeePassEntry {
	for _, entry := range db.Entries {
		if entry.KeyValues["Title"] == targetTitle {
			return &entry
		}
	}

	for _, subgroup := range db.Groups {
		entry := findEntry(&subgroup, targetTitle)
		if entry != nil {
			return entry
		}
	}

	return nil
}

func TestEntries(t *testing.T) {
	f, err := os.Open("testdata/onev4-add-attribute.kdbx")
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	db, err := decryptDatabase(f, "abc123")
	if err != nil {
		t.Fatal(err)
	}

	expectedKeyValues := map[string]string{
		"key":      "value",
		"Notes":    "notes notes notes",
		"Password": "fUBH7WxV8O9sBhvh",
		"Title":    "one",
		"URL":      "https://example.com",
		"UserName": "user",
	}

	entry := findEntry(&db.Root.Group, "one")

	if diff := cmp.Diff(expectedKeyValues, entry.KeyValues); diff != "" {
		t.Errorf("diff is wrong: %s", diff)
	}
}
