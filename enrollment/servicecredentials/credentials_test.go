package servicecredentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func privateFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if keyfile.Create(path, []byte("fixture")) != nil || os.WriteFile(path, []byte(value), 0600) != nil {
		t.Fatal("cannot create protected fixture")
	}
	return path
}

func TestProtectedDatabaseURL(t *testing.T) {
	value := "postgres://console:synthetic%21password@db.internal:5432/openuem?sslmode=verify-full&sslrootcert=%2Frun%2Ftrust%2Fdatabase.pem"
	for _, ending := range []string{"", "\n", "\r\n"} {
		actual, err := DatabaseURL("", privateFile(t, value+ending))
		if err != nil || actual != value {
			t.Fatal("protected database URL changed", err)
		}
	}
	for _, raw := range []string{value, "host=/private/socket user=console dbname=openuem"} {
		actual, err := DatabaseURL(raw, "")
		if err != nil || actual != raw {
			t.Fatal("legacy database grammar changed", err)
		}
	}
	for _, input := range []string{"", "https://user:synthetic-password@db.internal/db", "postgres://db.internal", "postgres:///db", "postgres:opaque", "postgres://user:synthetic-password@db.internal/db#fragment", "postgres://db.internal:invalid/db", "postgres://db.internal/db?sslmode=verify-full;unexpected=true", value + "\n\n", value + "\r", value + " ", value + "\x00", value + "é", strings.Repeat("p", 8195)} {
		actual, err := DatabaseURL("", privateFile(t, input))
		if !errors.Is(err, ErrConfiguration) || actual != "" || strings.Contains(err.Error(), "synthetic-password") {
			t.Fatal("invalid database input accepted or exposed")
		}
	}
	for _, sources := range [][2]string{{value, privateFile(t, value)}, {value, filepath.Join(t.TempDir(), "missing")}, {"", ""}} {
		if _, err := DatabaseURL(sources[0], sources[1]); !errors.Is(err, ErrConfiguration) {
			t.Fatal("ambiguous or missing database inputs accepted", err)
		}
	}
}

func TestProtectedEncryptionKey(t *testing.T) {
	key := strings.Repeat("x", 32)
	for _, ending := range []string{"", "\n", "\r\n"} {
		actual, err := EncryptionKey("", privateFile(t, key+ending))
		if err != nil || actual != key {
			t.Fatal("encryption key was transformed", err)
		}
	}
	if value, err := EncryptionKey(key, ""); err != nil || value != key {
		t.Fatal("raw AES key changed")
	}
	if value, err := EncryptionKey("", ""); err != nil || value != "" {
		t.Fatal("optional encryption key became mandatory")
	}
	for _, invalid := range []string{"", key + "x", key[:31], key + "\n\n", key + "\r", strings.Repeat(" ", 32), strings.Repeat("é", 16), strings.Repeat("x", 31) + "\x00"} {
		if value, err := EncryptionKey("", privateFile(t, invalid)); !errors.Is(err, ErrConfiguration) || value != "" {
			t.Fatal("invalid file encryption key accepted")
		}
	}
	if _, err := EncryptionKey("short", ""); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid raw AES length accepted")
	}
	if _, err := EncryptionKey(key, privateFile(t, key)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("competing encryption keys accepted")
	}
	if _, err := EncryptionKey(key, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid file fell back to raw encryption key")
	}
}

func TestProtectedInputsRejectUntrustedFiles(t *testing.T) {
	for _, mode := range []string{"missing", "directory", "symlink", "public"} {
		t.Run(mode, func(t *testing.T) {
			path := privateFile(t, strings.Repeat("x", 32))
			switch mode {
			case "missing":
				path += ".missing"
			case "directory":
				path = filepath.Dir(path)
			case "symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(path, link); err != nil {
					t.Skip("symbolic link privilege is unavailable")
				}
				path = link
			case "public":
				if runtime.GOOS == "windows" {
					t.Skip("native Windows ACL rejection is covered by keyfile tests")
				}
				if os.Chmod(path, 0644) != nil {
					t.Fatal("cannot set fixture permissions")
				}
			}
			if value, err := EncryptionKey("", path); !errors.Is(err, ErrConfiguration) || value != "" {
				t.Fatal("untrusted protected input accepted")
			}
		})
	}
}
