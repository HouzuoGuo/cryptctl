// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var mountOptionSeparator = regexp.MustCompile("[[:space:]]*,[[:space:]]*") // split mount options by commas
var consecutiveSpaces = regexp.MustCompile("[[:space:]]+")                 // split fields by consecutive spaces

// Represent a mount point entry in /etc/mtab.
type MountPoint struct {
	DeviceNode string
	MountPoint string
	FileSystem string
	Options    []string
	Dump       int
	Fsck       int
}

// Return true only if two mount points are identical in all attributes.
func (mount1 MountPoint) Equals(mount2 MountPoint) bool {
	return reflect.DeepEqual(mount1, mount2)
}

// Return the total size of the file system in Bytes.
func (mount MountPoint) GetFileSystemSizeByte() (int64, error) {
	fs := syscall.Statfs_t{}
	err := syscall.Statfs(mount.MountPoint, &fs)
	if err != nil {
		return 0, err
	}
	return fs.Bsize * int64(fs.Blocks), nil
}

// Remove btrfs subvolume among mount options. The MountPoint is modified in-place.
func (mount *MountPoint) DiscardBtrfsSubvolume() {
	newOptions := make([]string, 0, len(mount.Options))
	for _, opt := range mount.Options {
		// Discard "subvolid=" and "subvol="
		if !strings.HasPrefix(opt, "subvol") {
			newOptions = append(newOptions, opt)
		}
	}
	mount.Options = newOptions
}

// A list of mount points.
type MountPoints []MountPoint

// Find the first mount point that satisfies the given criteria. If a criteria is empty, it is ignored.
func (mounts MountPoints) GetByCriteria(deviceNode, mountPoint, fileSystem string) (MountPoint, bool) {
	for _, mount := range mounts {
		if (deviceNode == "" || mount.DeviceNode == deviceNode) &&
			(mountPoint == "" || mount.MountPoint == mountPoint) &&
			(fileSystem == "" || mount.FileSystem == fileSystem) {
			return mount, true
		}
	}
	return MountPoint{}, false
}

// Find the all mount points that satisfy the given criteria. If a criteria is empty, it is ignored.
func (mounts MountPoints) GetManyByCriteria(deviceNode, mountPoint, fileSystem string) (ret MountPoints) {
	ret = make([]MountPoint, 0, 0)
	for _, mount := range mounts {
		if (deviceNode == "" || mount.DeviceNode == deviceNode) &&
			(mountPoint == "" || mount.MountPoint == mountPoint) &&
			(fileSystem == "" || mount.FileSystem == fileSystem) {
			ret = append(ret, mount)
		}
	}
	return
}

// Find mount point for an arbitrary directory or file specified by an absolute path.
func (mounts MountPoints) GetMountPointOfPath(fileOrDirPath string) (MountPoint, bool) {
	if !filepath.IsAbs(fileOrDirPath) {
		return MountPoint{}, false
	}
	inputSegments := strings.Split(filepath.Clean(fileOrDirPath), fmt.Sprintf("%c", os.PathSeparator))
	// Special case for a single path segment - remove the tail empty element
	if inputSegments[len(inputSegments)-1] == "" {
		inputSegments = inputSegments[:len(inputSegments)-1]
	}
	var bestMatch MountPoint
	var bestMatchLen int
	for _, mp := range mounts {
		mpSegments := strings.Split(filepath.Clean(mp.MountPoint), fmt.Sprintf("%c", os.PathSeparator))
		// Special case for a single path segment - remove the tail empty element
		if mpSegments[len(mpSegments)-1] == "" {
			mpSegments = mpSegments[:len(mpSegments)-1]
		}
		if len(mpSegments) > len(inputSegments) {
			continue
		}
		if reflect.DeepEqual(inputSegments[0:len(mpSegments)], mpSegments) && len(mpSegments) > bestMatchLen {
			if len(mpSegments) == bestMatchLen && bestMatch.MountPoint != "" {
				// Return nothing in the unlikely case of two mount points owning the same directory/file
				return MountPoint{}, false
			}
			bestMatch = mp
			bestMatchLen = len(mpSegments)
		}
	}
	return bestMatch, bestMatch.MountPoint != ""
}

// Return all mount points defined in the input text except rootfs. Panic on malformed entry.
func ParseMountPoints(txt string) (mounts MountPoints) {
	mounts = make([]MountPoint, 0, 8)
	for _, line := range strings.Split(txt, "\n") {
		fields := consecutiveSpaces.Split(strings.TrimSpace(line), -1)
		if len(fields) == 0 || len(fields[0]) == 0 || fields[0][0] == '#' {
			continue // skip comments and empty lines
		}
		if len(fields) != 6 {
			panic(fmt.Sprintf("ParseMountPoints: incorrect number of fields in '%s'", line))
		}
		mountPoint := MountPoint{
			DeviceNode: fields[0],
			MountPoint: fields[1],
			FileSystem: fields[2],
		}
		if mountPoint.FileSystem == "rootfs" {
			// rootfs most likely originates from btrfs and masks the real mount point of /
			continue
		}
		// Split mount options
		mountPoint.Options = mountOptionSeparator.Split(fields[3], -1)
		var err error
		if mountPoint.Dump, err = strconv.Atoi(fields[4]); err != nil {
			panic(fmt.Sprintf("ParseMountPoints: not an integer in '%s'", line))
		}
		if mountPoint.Fsck, err = strconv.Atoi(fields[4]); err != nil {
			panic(fmt.Sprintf("ParseMountPoints: not an integer in '%s'", line))
		}
		mounts = append(mounts, mountPoint)
	}
	return
}

// Return all mount points that appear in /etc/mtab. Panic on error.
func ParseMtab() MountPoints {
	mounts, err := ioutil.ReadFile("/etc/mtab")
	if err != nil {
		panic(fmt.Errorf("ParseMtabMounts: failed to open /etc/mtab - %v", err))
	}
	return ParseMountPoints(string(mounts))
}
