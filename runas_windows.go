package runas

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output syscall_windows.go runas.go

const (
	SEE_MASK_DEFAULT            = 0x00000000
	SEE_MASK_CLASSNAME          = 0x00000001
	SEE_MASK_CLASSKEY           = 0x00000003
	SEE_MASK_IDLIST             = 0x00000004
	SEE_MASK_INVOKEIDLIST       = 0x0000000C
	SEE_MASK_ICON               = 0x00000010
	SEE_MASK_HOTKEY             = 0x00000020
	SEE_MASK_NOCLOSEPROCESS     = 0x00000040
	SEE_MASK_CONNECTNETDRV      = 0x00000080
	SEE_MASK_NOASYNC            = 0x00000100
	SEE_MASK_FLAG_DDEWAIT       = 0x00000100
	SEE_MASK_DOENVSUBST         = 0x00000200
	SEE_MASK_FLAG_NO_UI         = 0x00000400
	SEE_MASK_UNICODE            = 0x00004000
	SEE_MASK_NO_CONSOLE         = 0x00008000
	SEE_MASK_ASYNCOK            = 0x00100000
	SEE_MASK_NOQUERYCLASSSTORE  = 0x01000000
	SEE_MASK_HMONITOR           = 0x00200000
	SEE_MASK_NOZONECHECKS       = 0x00800000
	SEE_MASK_WAITFORINPUTIDLE   = 0x02000000
	SEE_MASK_FLAG_LOG_USAGE     = 0x04000000
	SEE_MASK_FLAG_HINST_IS_SITE = 0x08000000
)

const (
	SE_ERR_FNF             = 2
	SE_ERR_PNF             = 3
	SE_ERR_ACCESSDENIED    = 5
	SE_ERR_OOM             = 8
	SE_ERR_DLLNOTFOUND     = 32
	SE_ERR_SHARE           = 26
	SE_ERR_ASSOCINCOMPLETE = 27
	SE_ERR_DDETIMEOUT      = 28
	SE_ERR_DDEFAIL         = 29
	SE_ERR_DDEBUSY         = 30
	SE_ERR_NOASSOC         = 31
)

type shellExecuteInfo struct {
	size          uint32         // DWORD
	mask          uint32         // ULONG
	hwnd          windows.HWND   // HWND
	verb          *uint16        // LPCWSTR
	file          *uint16        // LPCWSTR
	parameters    *uint16        // LPCWSTR
	directory     *uint16        // LPCWSTR
	show          int32          // int
	instApp       windows.Handle // HINSTANCE
	IDList        uintptr        // *void
	class         *uint16        // LPCWSTR
	hkeyClass     windows.Handle // HKEY
	hotKey        uint32         // DWORD
	iconOrMonitor windows.Handle // HANDLE
	process       windows.Handle // HANDLE
}

//sys shellExecuteEx(pExecInfo *shellExecuteInfo) (success bool) = shell32.ShellExecuteExW

func shellExecuteError(code windows.Handle) error {
	switch code {
	case SE_ERR_FNF:
		return errors.New("file not found")
	case SE_ERR_PNF:
		return errors.New("path not found")
	case SE_ERR_ACCESSDENIED:
		return errors.New("access denied")
	case SE_ERR_OOM:
		return errors.New("out of memory")
	case SE_ERR_DLLNOTFOUND:
		return errors.New("dynamic library not found")
	case SE_ERR_SHARE:
		return errors.New("file already opened")
	case SE_ERR_ASSOCINCOMPLETE:
		return errors.New("file association incomplete")
	case SE_ERR_DDETIMEOUT:
		return errors.New("DDE operation timeout")
	case SE_ERR_DDEFAIL:
		return errors.New("DDE operation failed")
	case SE_ERR_DDEBUSY:
		return errors.New("DDE operation busy")
	case SE_ERR_NOASSOC:
		return errors.New("file association unavailable")
	default:
		return fmt.Errorf("error code %d", code)
	}
}

// RunElevated starts the given process with elevated priviledges.
// An UAC prompt is displayed to the user to confirm the action.
func RunElevated(executable, workingDir string, args []string, awaitProcCompletion bool) (int, error) {
	var verb, file, directory, parameters *uint16
	var err error

	if verb, err = windows.UTF16PtrFromString("runas"); err != nil {
		return 0, err
	}
	if file, err = windows.UTF16PtrFromString(executable); err != nil {
		return 0, err
	}
	if directory, err = windows.UTF16PtrFromString(workingDir); err != nil {
		return 0, err
	}
	if parameters, err = windows.UTF16PtrFromString(strings.Join(args, " ")); err != nil {
		return 0, err
	}

	execInfo := &shellExecuteInfo{
		size:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		verb:       verb,
		directory:  directory,
		file:       file,
		parameters: parameters,
		show:       windows.SW_SHOW, //HIDE,
		mask:       SEE_MASK_NOCLOSEPROCESS,
	}
	if !shellExecuteEx(execInfo) {
		return 0, shellExecuteError(execInfo.instApp)
	}

	if awaitProcCompletion {
		const STILL_ACTIVE = 259 // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess#remarks
		var exitCode uint32 = STILL_ACTIVE
		for exitCode == STILL_ACTIVE {
			time.Sleep(250 * time.Millisecond)
			if err := windows.GetExitCodeProcess(execInfo.process, &exitCode); err != nil {
				return 0, fmt.Errorf("waiting for process exit: %w", err)
			}
		}
		return int(exitCode), nil
	}
	return 0, nil
}

// IsAdminProcess returns true if the current process already
// runs as admin.
func IsAdminProcess() (bool, error) {
	return windows.GetCurrentProcessToken().IsElevated(), nil
}
