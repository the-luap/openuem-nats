package keyfile

import "errors"

var ErrCreate = errors.New("could not create a new protected credential file")

// Create writes a new credential without overwriting existing files or following
// an existing symlink. Access controls are private before the first byte is written.
// Failed writes remain protected and must not be treated as complete credentials.
func Create(path string, data []byte) error {
	if path == "" || len(data) == 0 || len(data) > 16<<20 {
		return ErrCreate
	}
	file, err := createExclusive(path)
	if err != nil {
		return ErrCreate
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || protected(file, info) != nil {
		return ErrCreate
	}
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
