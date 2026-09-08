package keyfile

import (
	"errors"
	"os"
)

var ErrCreate = errors.New("could not create a new protected credential file")

// Create writes a new credential without overwriting existing files or following
// an existing symlink. Access controls are private before the first byte is written.
// Failed writes remain protected and must not be treated as complete credentials.
func Create(path string, data []byte) error {
	if path == "" || len(data) == 0 || len(data) > 16<<20 {
		return ErrCreate
	}
	file, err := CreateFile(path)
	if err != nil {
		return ErrCreate
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return ErrCreate
	}
	if err = file.Sync(); err != nil {
		return ErrCreate
	}
	if err = file.Close(); err != nil {
		return ErrCreate
	}
	return nil
}

// CreateFile opens a new empty protected file for streaming without following or
// replacing an existing entry. Access controls are private before any write. The
// caller owns the descriptor, bounds writes, syncs completed content and closes
// it before publication/use. Interrupted writes remain protected but incomplete;
// this function does not publish a completed credential or remove failed files.
// The caller must select a protected parent and keep its ancestors trusted.
func CreateFile(path string) (*os.File, error) {
	if path == "" {
		return nil, ErrCreate
	}
	file, err := createExclusive(path)
	if err != nil {
		return nil, ErrCreate
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || protected(file, info) != nil {
		file.Close()
		return nil, ErrCreate
	}
	return file, nil
}
