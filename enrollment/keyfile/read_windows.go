package keyfile

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protected(file *os.File, _ os.FileInfo) error {
	security, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrPrivateFile
	}
	defer runtime.KeepAlive(security)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrPrivateFile
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !trusted(owner) {
		return ErrPrivateFile
	}
	dacl, _, err := security.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 128 {
		return ErrPrivateFile
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			return ErrPrivateFile
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrPrivateFile
		}
		// GetAce returns a kernel-validated variable-length SID beginning at
		// SidStart. Retain the descriptor while reading that embedded SID.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask != 0 && !trusted(sid) {
			return ErrPrivateFile
		}
	}
	return nil
}
