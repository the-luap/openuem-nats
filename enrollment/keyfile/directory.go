package keyfile

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrPrivateDirectory = errors.New("credential directory must be private and owned by the service or system administrator")

// CreateDirectory creates one private directory without creating parents or
// changing existing permissions. A pre-existing directory must already satisfy
// CheckDirectory. The caller must select a trusted parent; this function cannot
// make an attacker-writable ancestor safe.
func CreateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrPrivateDirectory
	}
	if err := createDirectory(path); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrPrivateDirectory
	}
	return CheckDirectory(path)
}

// CheckDirectory checks the opened directory's owner/access controls and rejects
// a final symlink or replacement during open. It does not traverse or chmod other
// directories. Callers must keep credential parents protected against renames.
func CheckDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrPrivateDirectory
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return ErrPrivateDirectory
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrPrivateDirectory
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.IsDir() || !os.SameFile(before, after) || protected(file, after) != nil {
		return ErrPrivateDirectory
	}
	return nil
}
