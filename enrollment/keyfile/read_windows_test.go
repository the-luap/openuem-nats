package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsCredentialFileRequiresPrivateDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.nkey")
	if err := os.WriteFile(path, []byte("test-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	set := func(value string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(value)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(descriptor)
	}
	private := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
	set(private)
	data, err := Read(path, 512)
	if err != nil || string(data) != "test-credential" {
		t.Fatal("private Windows credential rejected", err)
	}
	set(private + "(A;;GR;;;WD)")
	if _, err = Read(path, 512); !errors.Is(err, ErrPrivateFile) {
		t.Fatal("Everyone-readable credential accepted", err)
	}
	set(private)
	if _, err = Read(path, 3); !errors.Is(err, ErrPrivateFile) {
		t.Fatal("oversized credential accepted", err)
	}
}
