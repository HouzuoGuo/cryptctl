// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"syscall"
	"testing"
)

const (
	TEST_DIR_MODE     = 0741 // A very odd mode good for test case
	TEST_FILE_MODE    = 0531 // A very odd mode good for test case
	TEST_FILE_CONTENT = "good"
)

// Create a new file and its parent directories (if missing) and write some dummy content into it.
func MakeTestFile(paths ...string) {
	oldUmask := syscall.Umask(0)
	if err := os.MkdirAll(path.Join(paths[0:len(paths)-1]...), TEST_DIR_MODE); err != nil {
		panic(err)
	} else if err := ioutil.WriteFile(path.Join(paths...), []byte(TEST_FILE_CONTENT), TEST_FILE_MODE); err != nil {
		panic(err)
	}
	syscall.Umask(oldUmask)
}

/*
Make sure that all intermediate directories have appropriate permission, then make sure that the file itself has
appropriate permission and previously test content.
*/
func FilePermContentTest(t *testing.T, paths ...string) {
	for i := 2; i < len(paths)-1; i++ {
		st, err := os.Stat(path.Join(paths[0:i]...))
		if err != nil {
			panic(err)
		}
		if st.Mode().Perm() != TEST_DIR_MODE {
			t.Fatalf("%s incorrect mode - %v vs %v", path.Join(paths[0:i]...), st.Mode().Perm(), TEST_DIR_MODE)
		}
	}
	content, err := ioutil.ReadFile(path.Join(paths...))
	if err != nil || string(content) != TEST_FILE_CONTENT {
		t.Fatal(err, string(content))
	}
}

func TestMirrorFiles(t *testing.T) {
	// Mirror the wrong paths
	if err := MirrorFiles("/", "/tmp", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("/var", "/var/lib", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("//var/lib", "//./var//", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("", "/abc", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("/abc", "", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("/./", "//.", nil); err == nil {
		t.Fatal("did not error")
	} else if err := MirrorFiles("a/b", "c/d", nil); err == nil {
		t.Fatal("did not error")
	}

	// Mirror good files
	tmpDir, err := ioutil.TempDir("", "cryptctltest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	MakeTestFile(tmpDir, "Source", "Dir A", "Subdir 1", "File 1")
	MakeTestFile(tmpDir, "Source", "Dir A", "Subdir 1", "File 2")
	MakeTestFile(tmpDir, "Source", "Dir A", "Subdir 2", "File 1")
	MakeTestFile(tmpDir, "Source", "Dir A", "Subdir 2", "File 2")
	MakeTestFile(tmpDir, "Source", "Dir B", "Subdir 1", "File 1")
	MakeTestFile(tmpDir, "Source", "Dir B", "Subdir 1", "File 2")
	MakeTestFile(tmpDir, "Source", "Dir B", "Subdir 2", "File 1")
	MakeTestFile(tmpDir, "Source", "Dir B", "Subdir 2", "File 2")

	testMirror := func() {
		var out bytes.Buffer
		if err := MirrorFiles(path.Join(tmpDir, "Source"), path.Join(tmpDir, "Destination"), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.String()) < 100 {
			t.Fatal("output is too short", out.String())
		}
		if usage, err := FileSpaceUsage(tmpDir); err != nil || usage != int64(2*8*len(TEST_FILE_CONTENT)) {
			t.Fatal(err, usage)
		}
	}
	testFileContent := func() {
		FilePermContentTest(t, tmpDir, "Destination", "Dir A", "Subdir 1", "File 1")
		FilePermContentTest(t, tmpDir, "Destination", "Dir A", "Subdir 1", "File 2")
		FilePermContentTest(t, tmpDir, "Destination", "Dir A", "Subdir 2", "File 1")
		FilePermContentTest(t, tmpDir, "Destination", "Dir A", "Subdir 2", "File 2")
		FilePermContentTest(t, tmpDir, "Destination", "Dir B", "Subdir 1", "File 1")
		FilePermContentTest(t, tmpDir, "Destination", "Dir B", "Subdir 1", "File 2")
		FilePermContentTest(t, tmpDir, "Destination", "Dir B", "Subdir 2", "File 1")
		FilePermContentTest(t, tmpDir, "Destination", "Dir B", "Subdir 2", "File 2")
	}
	// No matter now many times the sequence is run, only one mirror should exist in the destination
	for i := 0; i < 10; i++ {
		testMirror()
		testFileContent()
	}
}

func TestSecureErase(t *testing.T) {
	filePath := "/tmp/cryptctl-erase-test"
	fileSize := ERASE_BLOCK_SIZE * 7 / 2
	defer os.Remove(filePath)
	// Create a sample file 3.5x the size of erasure block
	fh, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	byte1 := []byte{1}
	for i := 0; i < fileSize; i++ {
		fh.Write(byte1)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	// No more than 10 consecutive byte 1s shall appear after erasure
	if err := SecureErase(filePath, false); err != nil {
		t.Fatal(err)
	}
	fh, err = os.OpenFile(filePath, os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < fileSize; i += 10 {
		buf := make([]byte, 10)
		if _, err := fh.Read(buf); err != nil {
			t.Fatal(err)
		}
		byte1 := true
		for _, b := range buf {
			if b != 1 {
				byte1 = false
			}
		}
		if byte1 {
			t.Fatal("too many byte 1s", i)
		}
	}
	// Erase and delete

}

func TestIsFile(t *testing.T) {
	if FileContains("/", "haha") == nil {
		t.Fatal("did not error")
	}
	if err := FileContains("/etc/os-release", "certainly does not exist"); err == nil {
		t.Fatal("did not error")
	}
	if err := FileContains("/etc/os-release", "NAME"); err != nil {
		t.Fatal(err)
	}
}

func TestIsDir(t *testing.T) {
	if err := IsDir("/"); err != nil {
		t.Fatal(err)
	}
	if IsDir("/etc/os-release") == nil {
		t.Fatal("did not error")
	}
}
