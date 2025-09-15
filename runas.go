package runas

import (
	"errors"
	"fmt"
	"os"
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

func installDrivers() error {
	if !IsAdmin() {
		// if not elevated, relaunch by shellexecute with runas verb set
		var runas, execFile, currDir, args *uint16
		var err error

		if runas, err = windows.UTF16PtrFromString("runas"); err != nil {
			return err
		}
		if exe, err := os.Executable(); err != nil {
			return err
		} else if execFile, err = windows.UTF16PtrFromString(exe); err != nil {
			return err
		}
		if cwd, err := os.Getwd(); err != nil {
			return err
		} else if currDir, err = windows.UTF16PtrFromString(cwd); err != nil {
			return err
		}
		if args, err = windows.UTF16PtrFromString(strings.Join(os.Args[1:], " ")); err != nil {
			return err
		}

		execInfo := &shellExecuteInfo{
			size:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
			verb:       runas,
			directory:  currDir,
			file:       execFile,
			parameters: args,
			show:       windows.SW_SHOW, //HIDE,
			mask:       SEE_MASK_NOCLOSEPROCESS,
		}
		if !shellExecuteEx(execInfo) {
			return shellExecuteError(execInfo.instApp)
		}

		// Wait for process completion
		const STILL_ACTIVE = 259 // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess#remarks
		var exitCode uint32 = STILL_ACTIVE
		for exitCode == STILL_ACTIVE {
			time.Sleep(250 * time.Millisecond)
			if err := windows.GetExitCodeProcess(execInfo.process, &exitCode); err != nil {
				return fmt.Errorf("waiting for process exit: %w", err)
			}
		}
		if exitCode != 0 {
			return fmt.Errorf("process terminated with exitcode %d", exitCode)
		}
		return nil
	}

	fmt.Println("started")
	time.Sleep(4 * time.Second)
	fmt.Println("completed!")
	time.Sleep(time.Second)
	return nil
}

func IsAdmin() bool {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	fmt.Printf("admin %v\n", elevated)
	return elevated
}
