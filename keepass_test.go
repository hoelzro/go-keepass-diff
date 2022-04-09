package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

//go:embed one.kdbx
var one []byte

//go:embed two.kdbx
var two []byte

type diffTest struct {
	left           string
	right          string
	expectedOutput string
}

var tests = []diffTest{
	{left: "one.kdbx", right: "two.kdbx", expectedOutput: "expected.txt"},
}

func TestDiff(t *testing.T) {
	for _, test := range tests {
		t.Run(fmt.Sprintf("comparing %s and %s", test.left, test.right), func(t *testing.T) {
			b := &bytes.Buffer{}

			leftFile, err := os.Open(test.left)
			if err != nil {
				t.Fatal(err)
			}

			defer leftFile.Close()

			rightFile, err := os.Open(test.right)
			if err != nil {
				t.Fatal(err)
			}

			defer rightFile.Close()

			if err := diff(
				leftFile,
				rightFile,
				test.left,
				test.right,
				"abc123",
				b,
			); err != nil {
				t.Fatal(err)
			}

			expected, err := os.ReadFile(test.expectedOutput)
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
