package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateCredentialDirectoryCreationPreservesExistingData(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "identity")
	if err := CreateDirectory(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(path); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(path, "pending")
	if err := Create(secret, []byte("private credential fixture")); err != nil {
		t.Fatal(err)
	}
	if err := CreateDirectory(path); err != nil {
		t.Fatal("existing private directory rejected", err)
	}
	if data, err := Read(secret, 128); err != nil || string(data) != "private credential fixture" {
		t.Fatal("directory setup changed an existing credential", err)
	}
	if err := CreateDirectory(secret); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("file accepted as credential directory", err)
	}
	if err := CreateDirectory(filepath.Join(root, "missing", "identity")); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("created an unreviewed parent directory", err)
	}
	for _, path := range []string{"", "relative", filepath.Join(root, "absent")} {
		if err := CheckDirectory(path); !errors.Is(err, ErrPrivateDirectory) {
			t.Fatal("invalid directory accepted", err)
		}
	}
	if err := CreateDirectory("relative-identity-directory"); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("relative credential directory created", err)
	}
}

func TestPrivateCredentialDirectoryRejectsSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := CreateDirectory(real); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symbolic link creation is unavailable on this host")
	}
	if err := CheckDirectory(link); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("symbolic-link credential directory accepted", err)
	}
	if err := CreateDirectory(link); !errors.Is(err, ErrPrivateDirectory) {
		t.Fatal("existing symbolic link accepted during setup", err)
	}
}
