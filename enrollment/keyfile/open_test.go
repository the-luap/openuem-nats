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

func TestProtectedStreamingOpenUsesOwnedDescriptorAndEnforcesBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-staged-file")
	content := bytes.Repeat([]byte("staged installer fixture"), 1024)
	if err := Create(path, content); err != nil {
		t.Fatal(err)
	}
	file, err := Open(path, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(content)+1)))
	if err != nil || !bytes.Equal(data, content) {
		t.Fatal("streamed file changed", err)
	}
	if _, err := file.Write([]byte("must not write")); err == nil {
		t.Fatal("protected descriptor permitted writes")
	}
	for _, limit := range []int64{-1, 0, int64(len(content) - 1), (1 << 30) + 1} {
		if file, err := Open(path, limit); !errors.Is(err, ErrPrivateFile) {
			if file != nil {
				file.Close()
			}
			t.Fatal("invalid stream bound accepted", err)
		}
	}
	if file, err := Open(filepath.Dir(path), 1<<30); !errors.Is(err, ErrPrivateFile) {
		if file != nil {
			file.Close()
		}
		t.Fatal("directory accepted", err)
	}
	if runtime.GOOS != "windows" {
		alias := filepath.Join(filepath.Dir(path), "alias")
		if err := os.Symlink(path, alias); err != nil {
			t.Fatal(err)
		}
		if file, err := Open(alias, 1<<30); !errors.Is(err, ErrPrivateFile) {
			if file != nil {
				file.Close()
			}
			t.Fatal("final symlink accepted", err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if file, err := Open(path, 1<<30); !errors.Is(err, ErrPrivateFile) {
			if file != nil {
				file.Close()
			}
			t.Fatal("shared file accepted", err)
		}
	}
}
