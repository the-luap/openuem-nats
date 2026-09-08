package keyfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProtectedStreamingCreationKeepsPrivateIncompleteFilesAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "streamed-package")
	file, err := CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || protected(file, info) != nil || info.Size() != 0 {
		t.Fatal("stream was not private before writing", err)
	}
	chunk := bytes.Repeat([]byte("bounded fixture"), 1024)
	for range 4 {
		if _, err := file.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(path, int64(4*len(chunk)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(data, bytes.Repeat(chunk, 4)) {
		t.Fatal("streamed content changed", err)
	}
	if replacement, err := CreateFile(path); !errors.Is(err, ErrCreate) {
		if replacement != nil {
			replacement.Close()
		}
		t.Fatal("existing stream overwritten", err)
	}
	if runtime.GOOS != "windows" {
		alias := filepath.Join(filepath.Dir(path), "alias")
		if err := os.Symlink(path, alias); err != nil {
			t.Fatal(err)
		}
		if replacement, err := CreateFile(alias); !errors.Is(err, ErrCreate) {
			if replacement != nil {
				replacement.Close()
			}
			t.Fatal("stream creation followed alias", err)
		}
	}
	incompletePath := filepath.Join(t.TempDir(), "incomplete")
	incomplete, err := CreateFile(incompletePath)
	if err != nil {
		t.Fatal(err)
	}
	incomplete.Write([]byte("partial"))
	incomplete.Close()
	if data, err := Read(incompletePath, 1024); err != nil || string(data) != "partial" {
		t.Fatal("incomplete stream did not retain private access", err)
	}
}
