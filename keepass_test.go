package main

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/google/go-cmp/cmp"
)

//go:embed one.kdbx
var one []byte

//go:embed two.kdbx
var two []byte

//go:embed expected.txt
var expected string

func TestDiff(t *testing.T) {
	b := &bytes.Buffer{}
	if err := diff(
		bytes.NewReader(one),
		bytes.NewReader(two),
		"one.kdbx",
		"two.kdbx",
		"abc123",
		b,
	); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(expected, b.String()); diff != "" {
		t.Errorf("diff is wrong: %s", diff)
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
