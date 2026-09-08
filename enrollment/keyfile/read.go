// Package keyfile creates and reads bounded credential files with private local
// access controls. Endpoint encryption and rotation are separate responsibilities;
// this package never accepts a key through a command line.
package keyfile

import (
	"errors"
	"io"
	"os"
)

var ErrPrivateFile = errors.New("credential file must be a protected regular file")

func Read(path string, limit int64) ([]byte, error) {
	if path == "" || limit < 1 || limit > 16<<20 {
		return nil, ErrPrivateFile
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrPrivateFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrPrivateFile
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrPrivateFile
	}
	if err = protected(file, info); err != nil {
		return nil, ErrPrivateFile
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrPrivateFile
	}
	return data, nil
}
