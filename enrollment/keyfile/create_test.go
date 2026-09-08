package keyfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCreateProtectsCredentialsAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.seed")
	var successes atomic.Int32
	var jobs sync.WaitGroup
	for range 16 {
		jobs.Go(func() {
			if err := Create(path, []byte("test-private-seed")); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrCreate) {
				t.Error(err)
			}
		})
	}
	jobs.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent writers did not create exactly one credential")
	}
	data, err := Read(path, 512)
	if err != nil || string(data) != "test-private-seed" {
		t.Fatal("created credential is not privately readable", err)
	}
	if err = Create(path, []byte("replacement")); !errors.Is(err, ErrCreate) {
		t.Fatal("existing credential was overwritten", err)
	}
	current, err := Read(path, 512)
	if err != nil || !bytes.Equal(data, current) {
		t.Fatal("failed replacement changed credential", err)
	}
	for _, data := range [][]byte{nil, make([]byte, (16<<20)+1)} {
		if err = Create(filepath.Join(t.TempDir(), "invalid.seed"), data); !errors.Is(err, ErrCreate) {
			t.Fatal("invalid credential length accepted", err)
		}
	}
}

func TestCreateDoesNotFollowExistingSymlinks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.seed")
	if err := Create(target, []byte("existing credential")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.seed")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable on this runner")
	}
	if err := Create(link, []byte("replacement")); !errors.Is(err, ErrCreate) {
		t.Fatal("credential creation followed an existing symlink", err)
	}
	data, err := Read(target, 512)
	if err != nil || string(data) != "existing credential" {
		t.Fatal("symlink target was changed", err)
	}
}
