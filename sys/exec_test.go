// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package sys

import (
	"bytes"
	"strings"
	"testing"
)

func TestExec(t *testing.T) {
	if exitStatus, stdout, stderr, err := Exec(nil, nil, nil, "echo", "hi", "there"); exitStatus != 0 || stdout != "hi there\n" || stderr != "" || err != nil {
		t.Fatal(exitStatus, stdout, stderr, err)
	}
	if exitStatus, stdout, stderr, err := Exec(nil, nil, nil, "sh", "-c", "echo hi >&2"); exitStatus != 0 || stdout != "" || stderr != "hi\n" || err != nil {
		t.Fatal(exitStatus, stdout, stderr, err)
	}
	// Custom stdin and stdout
	grepInput := `aaa
bbbFINDMEbbb
cccFINDMEccc
ddd`
	var outBuf bytes.Buffer
	if exitStatus, stdout, stderr, err := Exec(bytes.NewReader([]byte(grepInput)), &outBuf, nil, "grep", "FINDME"); exitStatus != 0 || stdout != "" || stderr != "" || err != nil || outBuf.String() != "bbbFINDMEbbb\ncccFINDMEccc\n" {
		t.Fatal(exitStatus, stdout, outBuf.String(), stderr, err)
	}
	// Custom stdout
	var errBuf bytes.Buffer
	if exitStatus, stdout, stderr, err := Exec(nil, nil, &errBuf, "sh", "-c", "echo hi >&2"); exitStatus != 0 || stdout != "" || stderr != "" || err != nil || errBuf.String() != "hi\n" {
		t.Fatal(exitStatus, stdout, errBuf.String(), stderr, err)
	}
	// Special exit status
	if exitStatus, stdout, stderr, err := Exec(nil, nil, nil, "false"); exitStatus != 1 || stdout != "" || stderr != "" || err == nil {
		t.Fatal(exitStatus, stdout, stderr, err)
	}
}

func TestWalkProcs(t *testing.T) {
	var seen bool
	if err := WalkProcs(func(cmdLine []string) bool {
		if strings.Contains(cmdLine[0], "systemd") {
			seen = true
			return false
		}
		return true
	}); err != nil || !seen {
		t.Fatal(err, seen)
	}
}
