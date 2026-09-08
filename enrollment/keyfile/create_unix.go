//go:build !windows

package keyfile

import "os"

func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

func createDirectory(path string) error { return os.Mkdir(path, 0700) }
