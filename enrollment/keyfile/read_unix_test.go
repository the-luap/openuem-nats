//go:build !windows

package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialFileRejectsSharedPermissionsDirectoriesAndOversize(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "service.nkey")
	if err := os.WriteFile(path, []byte("test-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := Read(path, 512)
	if err != nil || string(data) != "test-credential" {
		t.Fatal("private credential rejected", err)
	}
	if _, err = Read(path, 3); !errors.Is(err, ErrPrivateFile) {
		t.Fatal("oversized credential accepted", err)
	}
	for _, mode := range []os.FileMode{0644, 0640, 0660, 0604} {
		if err = os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err = Read(path, 512); !errors.Is(err, ErrPrivateFile) {
			t.Fatal("shared credential permissions accepted", mode, err)
		}
	}
	if _, err = Read(directory, 512); !errors.Is(err, ErrPrivateFile) {
		t.Fatal("directory accepted", err)
	}
}

func TestSharedDirectoryIsRejectedWithoutChangingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(path); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("shared directory accepted", err)
	}
	if err := CreateDirectory(path); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("shared directory silently reused", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("setup changed existing directory permissions", err)
	}
}
