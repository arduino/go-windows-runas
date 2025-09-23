//go:build !windows

package runas

import "errors"

func RunElevated(executable, workingDir string, args []string, awaitProcCompletion bool) (int, error) {
	return 0, errors.New("RunElevated is only supported on Windows")
}

func IsAdminProcess() (bool, error) {
	return false, errors.New("IsAdminProcess is only supported on Windows")
}
