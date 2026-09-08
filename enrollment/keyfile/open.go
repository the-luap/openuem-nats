package keyfile

import "os"

// Open returns an owned read-only descriptor for a protected regular file whose
// current size is within limit. Unlike Read, it rejects a final symlink and checks
// that the opened file matches the preceding directory entry. It does not allocate
// file-sized buffers, allowing private staging of bounded installer packages.
// Callers must keep ancestors protected, bound stream reads and retain/recheck the
// same descriptor instead of reopening an attacker-replaceable path after hashing.
func Open(path string, limit int64) (*os.File, error) {
	if path == "" || limit < 1 || limit > 1<<30 {
		return nil, ErrPrivateFile
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrPrivateFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrPrivateFile
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > limit || protected(file, after) != nil {
		file.Close()
		return nil, ErrPrivateFile
	}
	return file, nil
}
