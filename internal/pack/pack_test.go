package pack

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func zipOf(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("{}"))
	}
	zw.Close()
	return buf.Bytes()
}

func TestRead(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		err   string
	}{
		{"ok", []string{"manifest.json", "tx/a.json"}, ""},
		{"traversal", []string{"../evil"}, "unsafe entry"},
		{"nested traversal", []string{"tx/../../evil"}, "unsafe entry"},
		{"absolute", []string{"/etc/passwd"}, "unsafe entry"},
		{"backslash", []string{"tx\\a.json"}, "unsafe entry"},
		{"duplicate", []string{"a", "a"}, "duplicate entry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			z := zipOf(t, c.files...)
			_, err := Read(bytes.NewReader(z), int64(len(z)))
			if c.err == "" && err != nil {
				t.Fatal(err)
			}
			if c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
				t.Fatalf("err=%v want %q", err, c.err)
			}
		})
	}
	if _, err := Read(bytes.NewReader([]byte("nope")), 4); err == nil {
		t.Fatal("non-zip accepted")
	}
}

func TestParseRecords(t *testing.T) {
	for _, in := range []string{"{}\n\n{}\n", "{}", "{\n"} {
		if _, err := ParseRecords([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
