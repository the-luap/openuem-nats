//go:build !windows

package keyfile

import (
	"os"
	"syscall"
)

func protected(_ *os.File, info os.FileInfo) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0077 != 0 {
		return ErrPrivateFile
	}
	return nil
}
