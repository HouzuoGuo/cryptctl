// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"bytes"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/sys"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	BIN_CRYPTSETUP  = "/sbin/cryptsetup"
	LUKS_CIPHER     = "aes-xts-plain64:PBKDF2-sha512"
	LUKS_HASH       = "sha512"
	LUKS_KEY_SIZE_S = "512"
	LUKS_KEY_SIZE_I = 512
)

// Call cryptsetup luksFormat on the block device node.
func CryptFormat(key []byte, blockDev, uuid string) error {
	if err := CheckBlockDevice(blockDev); err != nil {
		return err
	}
	_, stdout, stderr, err := sys.Exec(bytes.NewReader(key), nil, nil,
		BIN_CRYPTSETUP, "--batch-mode", "--cipher", LUKS_CIPHER, "--hash", LUKS_HASH, "--key-size", LUKS_KEY_SIZE_S,
		"luksFormat", "--key-file=-", blockDev, "--uuid="+uuid)
	if err != nil {
		return fmt.Errorf("CryptFormat: failed to format \"%s\" - %v %s %s", blockDev, err, stdout, stderr)
	}
	return nil
}

// Call cryptsetup luksOpen on the block device node.
func CryptOpen(key []byte, blockDev, name string) error {
	if err := CheckBlockDevice(blockDev); err != nil {
		return err
	}
	_, err := os.Stat(path.Join("/dev/mapper", name))
	if err == nil {
		return fmt.Errorf("CryptOpen: \"%s\" appears to have already been unlocked as \"%s\"", blockDev, name)
	}
	_, stdout, stderr, err := sys.Exec(bytes.NewReader(key), nil, nil,
		BIN_CRYPTSETUP, "--batch-mode", "luksOpen", "--key-file=-", blockDev, name)
	if err != nil {
		return fmt.Errorf("CryptOpen: failed to open \"%s\" as \"%s\" - %v %s %s", blockDev, name, err, stdout, stderr)
	}
	return nil
}

// Call cryptsetup erase on the block device node.
func CryptErase(blockDev string) error {
	if err := CheckBlockDevice(blockDev); err != nil {
		return err
	}
	_, stdout, stderr, err := sys.Exec(nil, nil, nil, BIN_CRYPTSETUP, "--batch-mode", "luksErase", blockDev)
	if err != nil {
		return fmt.Errorf("CryptErase: failed to erase \"%s\" - %v %s %s", blockDev, err, stdout, stderr)
	}
	/*
		luksErase only erases key slots, but there is still some information left on the disk.
		Write 1 MBytes of zeros into the beginning of the disk so that not even little bit of LUKS information is left.
	*/
	blkDev, err := os.OpenFile(blockDev, os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("CryptErase: failed to open \"%s\" - %v", blockDev, err)
	}
	var zeros [1024 * 1024]byte
	written, err := blkDev.Write(zeros[:])
	if written == 0 {
		return fmt.Errorf("CryptErase: failed to write into \"%s\" - %v", blockDev, err)
	} else if err := blkDev.Sync(); err != nil {
		return fmt.Errorf("CryptErase: failed to sync \"%s\" - %v", blockDev, err)
	} else if err := blkDev.Close(); err != nil {
		return fmt.Errorf("CryptErase: failed to close \"%s\" - %v", blockDev, err)
	}
	return nil
}

// Call cryptsetup luksClose on the mapped device node.
func CryptClose(name string) error {
	_, stdout, stderr, err := sys.Exec(nil, nil, nil,
		BIN_CRYPTSETUP, "--batch-mode", "luksClose", name)
	if err != nil {
		return fmt.Errorf("CryptClose: failed to close \"%s\" - %v %s %s", name, err, stdout, stderr)
	}
	return nil
}

// Represent a cryptsetup mapping currently effective on the system.
type CryptMapping struct {
	Type    string
	Cipher  string
	KeySize int
	Device  string
	Loop    string
}

// Return true only if all fields (except Loop) are assigned.
func (mapping CryptMapping) IsValid() bool {
	return mapping.Type != "" && mapping.Cipher != "" && mapping.KeySize > 0 && mapping.Device != ""
}

// Return cryptsetup status (a device mapper device) parsed from the text.
func ParseCryptStatus(txt string) (mapping CryptMapping) {
	// The output is very simple to parse
	for _, line := range strings.Split(txt, "\n") {
		line = strings.TrimSpace(line)
		if typeLine := strings.TrimPrefix(line, "type:"); typeLine != line {
			mapping.Type = strings.TrimSpace(typeLine)
		} else if cipherLine := strings.TrimPrefix(line, "cipher:"); cipherLine != line {
			mapping.Cipher = strings.TrimSpace(cipherLine)
		} else if keySizeLine := strings.TrimPrefix(line, "keysize:"); keySizeLine != line {
			var err error
			mapping.KeySize, err = strconv.Atoi(strings.TrimSpace(strings.TrimRight(keySizeLine, "bits")))
			if err != nil {
				panic(fmt.Errorf("CryptStatus: failed to parse key size output on line \"%s\"", line))
			}
		} else if deviceLine := strings.TrimPrefix(line, "device:"); deviceLine != line {
			mapping.Device = strings.TrimSpace(deviceLine)
		} else if loopLine := strings.TrimPrefix(line, "loop:"); loopLine != line {
			mapping.Loop = strings.TrimSpace(loopLine)
		}
	}
	return
}

// Get luks device status. An error will be returned if the mapping status cannot be retrieved.
func CryptStatus(name string) (mapping CryptMapping, err error) {
	_, stdout, _, _ := sys.Exec(nil, nil, nil, BIN_CRYPTSETUP, "status", name)
	mapping = ParseCryptStatus(stdout)
	if !mapping.IsValid() {
		err = fmt.Errorf("CryptStatus: failed to retrieve a valid output for \"%s\", gathered information is: %+v", name, mapping)
	}
	return
}
