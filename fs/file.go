// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	BIN_RSYNC        = "/usr/bin/rsync"
	ERASE_NUM_PASS   = 10
	ERASE_BLOCK_SIZE = 128 * 1024
)

// Test whether file at the specified path can be read and contains the string. Case is sensitive.
func FileContains(paths, substr string) error {
	if paths == "" {
		return errors.New("Input path is empty")
	}
	if _, err := os.Stat(paths); os.IsNotExist(err) {
		return fmt.Errorf("File \"%s\" does not exist", paths)
	}
	content, err := ioutil.ReadFile(paths)
	if err != nil {
		return fmt.Errorf("Failed to read file \"%s\" - %v", paths, err)
	}
	if !strings.Contains(string(content), substr) {
		return fmt.Errorf("File \"%s\" does not contain keyword \"%s\"", paths, substr)
	}
	return nil
}

// Test whether the specified directory can be read.
func IsDir(paths string) error {
	st, err := os.Stat(paths)
	if err == nil {
		if st.IsDir() {
			return nil
		} else {
			return fmt.Errorf("\"%s\" is not a directory", paths)
		}
	} else {
		if os.IsNotExist(err) {
			return fmt.Errorf("Directory \"%s\" does not exist", paths)
		} else {
			return fmt.Errorf("Failed to read directory \"%s\" - %v", paths, err)
		}
	}
}

/*
Call rsync to recursively copy all files under source directory, including all file attributes/links, to the
destination directory. If supplied, rsync progress output will be copied to the output stream.
If some files already exist in the destination and the source files are newer, they will be overwritten.
Both source directory and destination directory must be absolute.
*/
func MirrorFiles(srcDir, destDir string, progressOut io.Writer) error {
	// Validate input paths
	srcDir = path.Clean(srcDir)
	destDir = path.Clean(destDir)
	if len(srcDir) < 2 || srcDir[0] != '/' {
		return fmt.Errorf("MirrorFiles: source \"%s\" should not be / and must be an absolute path", srcDir)
	} else if len(destDir) < 2 || destDir[0] != '/' {
		return fmt.Errorf("MirrorFiles: destination \"%s\" should not be / and must be an absolute path", destDir)
	} else if srcDir == destDir {
		return fmt.Errorf("MirrorFiles: source and destination directories are both \"%s\"", destDir)
	} else if strings.HasPrefix(destDir, srcDir) || strings.HasPrefix(srcDir, destDir) {
		return fmt.Errorf("MirrorFiles: source \"%s\" and destination \"%s\" directory should not overlap", srcDir, destDir)
	}
	// Enhance storage persistence before and after the operation
	syscall.Sync()
	defer syscall.Sync()
	// Source must be a directory
	if st, err := os.Stat(srcDir); err != nil {
		return fmt.Errorf("MirrorFiles: cannot read source directory \"%s\" - %v", srcDir, err)
	} else if !st.IsDir() {
		return fmt.Errorf("MirrorFiles: source location \"%s\" is not a directory", srcDir)
	}
	// Make the destination directory if it does not exist
	makeDestDir := false
	if st, err := os.Stat(destDir); os.IsNotExist(err) {
		makeDestDir = true
	} else if err != nil {
		return fmt.Errorf("MirrorFiles: cannot read destination directory \"%s\" - %v", srcDir, err)
	} else if !st.IsDir() {
		return fmt.Errorf("MirrorFiles: destination location \"%s\" is not a directory", srcDir)
	}
	// Lint source and destination path parameters to fit into rsync convention
	if srcDir[len(srcDir)-1] != '/' {
		srcDir += "/"
	}
	if destDir[len(destDir)-1] == '/' {
		destDir = destDir[0 : len(destDir)-1]
	}
	if !makeDestDir {
		destDir += "/"
	}
	/*
		Start mirroring:
		- a - archive; recursive; preserve symlinks, permissions, modification times, group&owner, device and special files.
		- H - preserve hardlinks
		- A - preserve ACLs and permissions
		- X - preserve extended attributes
		- x - do not cross file system boundaries
		- S - handle sparse files
		- W - copy whole files without using delta algorithm
		- v - show copied files in standard output
	*/
	cmd := exec.Command(BIN_RSYNC, "-aHAXxSWv", srcDir, destDir)
	cmd.Stdout = progressOut
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

// Count the total space usage of the specified path; the path can be either a file or a directory.
func FileSpaceUsage(paths string) (totalSize int64, err error) {
	err = filepath.Walk(paths, func(thisPath string, thisFile os.FileInfo, thisErr error) error {
		if thisErr != nil {
			return thisErr
		}
		if !thisFile.IsDir() {
			totalSize += thisFile.Size()
		}
		return nil
	})
	return
}

/*
Securely erase a file by overwriting it 10 times with random data, then delete the file.
Needless to say this function is painfully slow.
It relies on a vital assumption that the file system will overwrite data in place, bear in mind that many modern
file systems and hardware designs do not satisfy the assumption, here are some examples:
- Metadata/data journal.
- Data compression.
- Transient or persistent cache.
- Additional redundancy mechanisms such as RAID.
*/
func SecureErase(filePath string, delete bool) error {
	fh, err := os.OpenFile(filePath, os.O_RDWR, 0000)
	if err != nil {
		return err
	}
	defer fh.Close()

	fileSize, err := fh.Seek(0, 2)
	if err != nil {
		return err
	}
	// Overwrite 10 passes
	for pass := 0; pass < ERASE_NUM_PASS; pass++ {
		if _, err := fh.Seek(0, 0); err != nil {
			return err
		}
		for i := int64(0); i < fileSize; i += ERASE_BLOCK_SIZE {
			// Generate a block of random data gathered from kernel's cryptographic entropy pool
			sizeOfBlock := int64(ERASE_BLOCK_SIZE)
			if fileSize-i < ERASE_BLOCK_SIZE {
				// Avoid writing beyond EOF
				sizeOfBlock = fileSize - i
			}
			randData := make([]byte, sizeOfBlock)
			if _, err := rand.Read(randData); err != nil {
				panic(fmt.Errorf("SecureErase: failed to read %d bytes from random source", ERASE_BLOCK_SIZE))
			}
			// Write the block of random data and sync to storage
			if _, err := fh.Write(randData); err != nil {
				return err
			} else if err := fh.Sync(); err != nil {
				return err
			}
		}
	}
	if err := fh.Close(); err != nil {
		return err
	} else if delete {
		return os.Remove(filePath)
	}
	return nil
}
