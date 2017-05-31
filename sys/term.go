// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package sys

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var TermEcho bool = true // keep track of the latest change to terminal echo  made by SetTermEcho function

// Enable or disable terminal echo.
func SetTermEcho(echo bool) {
	term := &syscall.Termios{}
	stdout := os.Stdout.Fd()
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, stdout, syscall.TCGETS, uintptr(unsafe.Pointer(term)))
	if err != 0 {
		log.Printf("SetTermEcho: syscall failed - %v", err)
	}
	if echo {
		term.Lflag |= syscall.ECHO
	} else {
		term.Lflag &^= syscall.ECHO
	}
	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, stdout, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(term)))
	if err != 0 {
		log.Printf("SetTermEcho: syscall failed - %v", err)
	}
	TermEcho = echo
}

/*
Print a prompt in stdout and return a trimmed line read from stdin.
If mandatory switch is turned on, the function will keep asking for an input if default hint is unavailable.
*/
func Input(mandatory bool, defaultHint string, format string, values ...interface{}) string {
	if defaultHint == "" {
		fmt.Printf(format+": ", values...)
	} else {
		fmt.Printf(format+" ["+defaultHint+"]: ", values...)
	}
	for {
		str, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Panicf("Input: failed to read from stadard input - %v", err)
		}
		str = strings.TrimSpace(str)
		if str == "" && mandatory && defaultHint == "" {
			if !TermEcho {
				fmt.Println()
			}
			fmt.Print("Please enter a value: ")
			os.Stdout.Sync()
			continue
		}
		return str
	}
}

// Disable terminal echo and read a password input from stdin, then re-enable terminal echo.
func InputPassword(mandatory bool, defaultHint string, format string, values ...interface{}) string {
	SetTermEcho(false)
	defer SetTermEcho(true)
	ret := Input(mandatory, defaultHint, format, values...)
	fmt.Println() // because the new-line character was not echoed by password entry
	return ret
}

// Print a prompt in stdout and return an integer read from stdin.
func InputInt(mandatory bool, defaultHint, lowerLimit, upperLimit int, format string, values ...interface{}) int {
	for {
		valStr := Input(mandatory, strconv.Itoa(defaultHint), format, values...)
		if valStr == "" {
			return defaultHint
		}
		valInt, err := strconv.Atoi(valStr)
		if err != nil {
			fmt.Println("Please enter a whole number.")
			continue
		}
		if valInt < lowerLimit || valInt > upperLimit {
			fmt.Printf("Please enter a number between %d and %d.\n", lowerLimit, upperLimit)
			continue
		}
		return valInt
	}
}

// Print a prompt in stdout and return a boolean value read from stdin.
func InputBool(format string, values ...interface{}) bool {
	fmt.Printf(format+": ", values...)
	for {
		str, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Panicf("Input: failed to read from stadard input - %v", err)
		}
		switch strings.TrimSpace(strings.ToLower(str)) {
		case "y":
			fallthrough
		case "yes":
			fallthrough
		case "ja":
			return true
		case "n":
			fallthrough
		case "no":
			fallthrough
		case "nein":
			return false
		default:
			fmt.Print("Please enter \"yes\" or \"no\": ")
			os.Stdout.Sync()
			continue
		}
	}
}

// Print a prompt in stdout and return a file path (must exist be absolute) read from stdin.
func InputAbsFilePath(mandatory bool, defaultHint string, format string, values ...interface{}) string {
	for {
		val := Input(mandatory, defaultHint, format, values...)
		if val == "" {
			return val
		}
		if val[0] != '/' {
			fmt.Println("Please enter an absolute path led by a slash.")
			continue
		}
		if _, err := os.Stat(val); err != nil {
			fmt.Printf("The location \"%s\" cannot be read, please double check your input.\n", val)
			continue
		}
		return val
	}
}
