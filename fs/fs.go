// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"bytes"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/sys"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	BIN_MKFS   = "/usr/sbin/mkfs"
	BIN_LSBLK  = "/usr/bin/lsblk"
	BIN_MOUNT  = "/usr/bin/mount"
	BIN_UMOUNT = "/usr/bin/umount"
)

var lsblkFields = regexp.MustCompile(`"((?:\\"|[^"])*)"`) // extract values from lsblk output

// Represent a block device currently detected on the system.
type BlockDevice struct {
	UUID       string
	Name       string // Name is the device node name
	Path       string // full path to the device node under /dev including the prefix
	Type       string // device type can be: partition, disk, encrypted, etc..
	FileSystem string
	MountPoint string
	SizeByte   int64
	PKName     string // PKName is the underlying block device's node name of a crypt block device
}

// Return true if the block device is LUKS encrypted.
func (blkDev BlockDevice) IsLUKSEncrypted() bool {
	return blkDev.FileSystem == "crypto_LUKS"
}

// A list of block devices.
type BlockDevices []BlockDevice

// Find the first block device that satisfies the given criteria. If a criteria is empty, it is ignored.
func (blkDevs BlockDevices) GetByCriteria(uuid, devPath, devType, fileSystem, mountPoint, pkName, name string) (BlockDevice, bool) {
	for _, blkDev := range blkDevs {
		if (uuid == "" || blkDev.UUID == uuid) &&
			(devPath == "" || blkDev.Path == devPath) &&
			(devType == "" || blkDev.Type == devType) &&
			(fileSystem == "" || blkDev.FileSystem == fileSystem) &&
			(mountPoint == "" || blkDev.MountPoint == mountPoint) &&
			(pkName == "" || blkDev.PKName == pkName) &&
			(name == "" || blkDev.Name == name) {
			return blkDev, true
		}
	}
	return BlockDevice{}, false
}

/*
Return all block devices defined in the input text.
The input text is presumed to be obtained from the following command's output:
  lsblk -P -b -o UUID,KNAME,TYPE,FSTYPE,MOUNTPOINT,SIZE
*/
func ParseBlockDevs(txt string) BlockDevices {
	ret := make([]BlockDevice, 0, 8)
	for _, line := range strings.Split(txt, "\n") {
		fields := lsblkFields.FindAllString(line, -1)
		if len(fields) < 7 {
			continue // skip empty lines
		}
		// Remove surrounding quotes from match
		for fi, field := range fields {
			fields[fi] = field[1 : len(field)-1]
		}
		devPath := "/dev/" + fields[1]
		devType := fields[2]
		if devType == "crypt" {
			devPath = "/dev/mapper/" + fields[1]
		}
		blkDev := BlockDevice{
			UUID:       fields[0],
			Name:       fields[1],
			Path:       devPath,
			Type:       devType,
			FileSystem: fields[3],
			MountPoint: fields[4],
			PKName:     fields[6],
		}
		// Block device size can be empty
		if fields[5] != "" {
			iByte, intErr := strconv.ParseUint(fields[5], 10, 64)
			if intErr != nil {
				panic(fmt.Errorf("ParseBlockDevs: failed to parse size number in line \"%s\"", line))
			}
			blkDev.SizeByte = int64(iByte)
		}
		ret = append(ret, blkDev)
	}
	return ret
}

// Return all block devices currently detected on the system.
func GetBlockDevices() BlockDevices {
	/*
		-P - generate output in a way processable by programs.
		-b - block device size is in bytes.
		-o - choose output columns.

		The parser reads NAME instead of KNAME because KNAME does not apply for names under /dev/mapper.
	*/
	_, stdout, stderr, err := sys.Exec(nil, nil, nil, BIN_LSBLK, "-P", "-b", "-o", "UUID,NAME,TYPE,FSTYPE,MOUNTPOINT,SIZE,PKNAME")
	if err != nil {
		panic(fmt.Errorf("GetBlockDevices: failed to execute lsblk - %v %s %s", err, stdout, stderr))
	}
	return ParseBlockDevs(stdout)
}

// Return information about the specific block device.
// The path of block device in return value will match the input device node path.
func GetBlockDevice(node string) (blkDev BlockDevice, found bool) {
	if !strings.HasPrefix(node, "/dev/") {
		node = "/dev/" + node
	}
	/*
		-P - generate output in a way processable by programs.
		-b - block device size is in bytes.
		-o - choose output columns.
	*/
	_, stdout, _, _ := sys.Exec(nil, nil, nil, BIN_LSBLK, "-P", "-b", "-o", "UUID,NAME,TYPE,FSTYPE,MOUNTPOINT,SIZE,PKNAME", node)
	blkDevs := ParseBlockDevs(stdout)
	found = len(blkDevs) > 0
	if found {
		blkDev = blkDevs[0]
		blkDev.Path = node
	}
	return
}

// Return nil if the file specified is a block device. Return an error otherwise.
func CheckBlockDevice(filePath string) error {
	if !strings.HasPrefix(filePath, "/dev/") {
		return fmt.Errorf("CheckBlockDevice: \"%s\" is not from /dev", filePath)
	}
	st, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("CheckBlockDevice: cannot read \"%s\"", filePath)
	} else if st.Sys().(*syscall.Stat_t).Mode&syscall.S_IFBLK != syscall.S_IFBLK {
		return fmt.Errorf("CheckBlockDevice: \"%s\" is not a block device", filePath)
	}
	return nil
}

// Call mkfs to make a new file system on the block device.
func Format(blockDev, fsType string) error {
	if err := CheckBlockDevice(blockDev); err != nil {
		return err
	}
	cmd := exec.Command(BIN_MKFS, "-t", fsType, blockDev)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Format: failed to format \"%s\" - %v %s", blockDev, err, out)
	}
	return nil
}

// Call mount to mount a file system. The mounted file system will be exposed to all processes on the computer.
func Mount(blockDev, fsType string, fsOptions []string, mountPoint string) error {
	if err := CheckBlockDevice(blockDev); err != nil {
		return err
	}
	var cmd *exec.Cmd
	params := make([]string, 0, 8)
	params = append(params, "--make-shared")
	if fsType != "" {
		params = append(params, "-t", fsType)
	}
	if fsOptions != nil && len(fsOptions) > 0 {
		params = append(params, "-o", strings.Join(fsOptions, ","))
	}
	params = append(params, blockDev, mountPoint)
	cmd = exec.Command(BIN_MOUNT, params...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Mount: failed to mount \"%s\" on \"%s\" using options \"%s\" - %v %s", blockDev, mountPoint, strings.Join(fsOptions, ","), err, out)
	}
	return nil
}

// GetSystemdMountNameForDir returns systemd's mount unit associated with the directory, supposedly a mount point.
func GetSystemdMountNameForDir(dirPath string) string {
	var ret bytes.Buffer
	for i, ch := range dirPath {
		if i == 0 && ch == '/' {
			continue
		} else if ch == '/' {
			ret.WriteRune('-')
		} else if ch >= 48 && ch <= 57 || ch >= 65 && ch <= 90 || ch >= 97 && ch <= 122 {
			ret.WriteRune(ch)
		} else {
			ret.WriteString(fmt.Sprintf("\\x%x", ch))
		}
	}
	return ret.String() + ".mount"
}

// Umount un-mounts a file system by interacting with systemd.
func Umount(mountPoint string) error {
	err1 := sys.SystemctlStop(GetSystemdMountNameForDir(mountPoint))
	out, err2 := exec.Command(BIN_UMOUNT, mountPoint).CombinedOutput()
	devs := GetBlockDevices()
	if _, found := devs.GetByCriteria("", "", "", "", mountPoint, "", ""); !found {
		return nil
	}
	return fmt.Errorf("Umount: first attempt failed with error \"%v\", and second attempt failed with output \"%s\" and error \"%v\"", err1, out, err2)
}

// Return amount of free space available on the disk where input paths is mounted on.
func FreeSpace(paths string) (int64, error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(paths, &stats); err != nil {
		return 0, fmt.Errorf("Failed to calculate free space on \"%s\" - %v", paths, err)
	}
	return stats.Bsize * int64(stats.Blocks), nil
}
