// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package sys

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
)

/*
Run an external program, wait till it finishes execution, eventually return its exit status.
Optionally return the program output only if stdout/stderr are left nil.
*/
func Exec(stdin io.Reader, stdout, stderr io.Writer, programName string, programArgs ...string) (exitStatus int,
	stdoutStr, stderrStr string, execErr error) {
	cmd := exec.Command(programName, programArgs...)
	// Connect IO
	var myStdout, myStderr bytes.Buffer
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	if stdout == nil {
		cmd.Stdout = &myStdout
	}
	cmd.Stderr = stderr
	if stderr == nil {
		cmd.Stderr = &myStderr
	}
	// Run process and wait
	if execErr = cmd.Run(); execErr != nil {
		// Figure out the exit status
		if exitErr, isExit := execErr.(*exec.ExitError); isExit {
			if status, isStatus := exitErr.Sys().(syscall.WaitStatus); isStatus {
				exitStatus = status.ExitStatus()
			}
		}
		stdoutStr = myStdout.String()
		stderrStr = myStderr.String()
		return
	}
	stdoutStr = myStdout.String()
	stderrStr = myStderr.String()
	return
}

// Lock all program memory into main memory to prevent sensitive data from leaking into swap.
func LockMem() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Please run cryptctl with root privilege.")
		os.Exit(111)
	}
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to lock memory - %v", err)
		os.Exit(111)
	}
}

/*
Print the message to stderr and exit the program with status 1.
The function does not return, however it is defined to have a return value to help with coding style.
*/
func ErrorExit(template string, stuff ...interface{}) int {
	fmt.Fprintf(os.Stderr, template+"\n", stuff...)
	os.Exit(1)
	return 1
}

// Run function on all running processes that are exposed via /proc.
func WalkProcs(fun func(cmdLine []string) bool) error {
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		cmdline, err := ioutil.ReadFile(path.Join(entry, "cmdline"))
		if err != nil {
			// process is gone
			continue
		}
		cmdLineStr := make([]string, 0, 0)
		for _, seg := range bytes.Split(cmdline, []byte{0}) {
			cmdLineStr = append(cmdLineStr, string(seg))
		}
		if !fun(cmdLineStr) {
			return nil
		}
	}
	return nil
}
