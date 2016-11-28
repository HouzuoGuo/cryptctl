// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/keyrpc"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	DM_NAME_PREFIX                = "cryptctl-unlocked-"
	SRC_DIR_NEW_NAME_PREFIX       = "cryptctl-moved-"
	MSG_E_ILLEGAL_PATH            = "Please specify absolute directory/file path in all path parameters"
	MSG_E_SRC_DIR_MOUNT_NOT_FOUND = "Failed to determine the mount point of directory \"%s\"."
	MSG_E_ENCRYPT_DISK_NOT_FOUND  = "Cannot find disk \"%s\". See output of \"lsblk\" command to determine available disks."
	MSG_E_MOUNT_UNDERNEATH        = "The directory to encrypt has a mount point (\"%s\") underneath, please unmount all drives underneath before proceeding with encryption."
	MSG_E_ENC_ALREADY_OPEN        = "The disk to encrypt (\"%s\") is being actively used as an encrypted disk (\"%s\"), please destroy its data and try again."
	MSG_E_CALC_DIR_SIZE           = "Failed to calculate size of directory \"%s - %v"
	MSG_E_DISK_TOO_SMALL          = "Disk \"%s\" is too small to hold encrypted data. It should have at least %d MBytes in capacity."
	MSG_E_WALK_PROC               = "Failed to inspect running processes - %v"
	MSG_E_SRC_DIR_NESTED_IN_DISK  = "The directory to encrypt \"%s\" is located on disk \"%s\". Please choose a different disk to be the encrypted disk."
	MSG_E_SAP_RUNNING             = "You appear to be encrypting an SAP directory, but an SAP process (\"%s\") is still running, please shut it down."
	MSG_E_ENC_REMOTE_FS           = "\"%s\" appear to be a remote file system (e.g. NFS or CIFS), but this utility can only encrypt local file systems."
	MSG_STEP_1                    = "\n1. Completely erase disk \"%s\" and install encryption key on it.\n"
	MSG_STEP_2                    = "\n2. Copy data from \"%s\" into the disk.\n"
	MSG_STEP_3                    = "\n3. Announce the encrypted disk to key server \"%s\".\n"
	MSG_E_NO_RAND                 = "Failed to generate encryption key - %v"
	MSG_E_MKDIR                   = "Failed to make directory \"%s\" - %v"
	MSG_E_RENAME_DIR              = "Failed to rename directory \"%s\" into \"%s\" - %v"
	MSG_E_NO_DEV_INFO             = "Failed to retrieve block device information of \"%s\""
	MSG_E_RPC_KEY_SAVE            = "Failed to upload key record: %v"
	MSG_OK_CONGRATS               = "\nCongratulations! Data in \"%s\" is now safely encrypted in \"%s\".\nRemember to manually delete the original un-encrypted copy in \"%s\".\n"
)

// Return a computed mapper device name from a crypto device name.
func MakeDeviceMapperName(devName string) string {
	if strings.Contains(devName, "/") {
		return DM_NAME_PREFIX + path.Base(devName)
	}
	return DM_NAME_PREFIX + devName
}

// Validate all pre-conditions for setting up encryption on the disk.
func EncryptFSPreCheck(srcDir, encDisk string) error {
	// Input paths should exist
	if srcDir == "" || srcDir == "." || encDisk == "" || encDisk == "." || !filepath.IsAbs(srcDir) || !filepath.IsAbs(encDisk) {
		return errors.New(MSG_E_ILLEGAL_PATH)
	}
	if err := fs.IsDir(srcDir); err != nil {
		return err
	}
	if err := fs.CheckBlockDevice(encDisk); err != nil {
		return err
	}
	// Remove suffix slash from srcDir
	if strings.HasSuffix(srcDir, "/") {
		srcDir = srcDir[:len(srcDir)-1]
	}

	mountPoints := fs.ParseMtab()
	blkDevs := fs.GetBlockDevices()
	// No mount point may be located underneath the directory to encrypt because it is about to be copied
	for _, mountPoint := range mountPoints {
		if strings.HasPrefix(mountPoint.MountPoint, srcDir) && mountPoint.MountPoint != srcDir {
			return fmt.Errorf(MSG_E_MOUNT_UNDERNEATH, mountPoint.MountPoint)
		}
	}
	// The disk to encrypt may not have partitions underneath that are already mounted
	if !unicode.IsDigit(rune(encDisk[len(encDisk)-1])) {
		for _, mp := range mountPoints {
			if strings.HasPrefix(mp.DeviceNode, encDisk) {
				if unicode.IsDigit(rune(mp.DeviceNode[len(encDisk)])) {
					return fmt.Errorf(MSG_E_MOUNT_UNDERNEATH, mp.MountPoint)
				}
			}
		}
	}
	// The disk to encrypt may not already be encrypted and opened
	dmName := MakeDeviceMapperName(encDisk)
	if openedEncDev, found := blkDevs.GetByCriteria("", "/dev/mapper/"+dmName, "", "", ""); found {
		return fmt.Errorf(MSG_E_ENC_ALREADY_OPEN, encDisk, openedEncDev.Path)
	}
	// The directory to encrypt may not be mounted from the disk to encrypt
	srcDirMount, found := mountPoints.GetMountPointOfPath(srcDir)
	if !found {
		return fmt.Errorf(MSG_E_SRC_DIR_MOUNT_NOT_FOUND, srcDir)
	} else if srcDirMount.DeviceNode == encDisk {
		return fmt.Errorf(MSG_E_SRC_DIR_NESTED_IN_DISK, srcDir, encDisk)
	} else if strings.HasPrefix(srcDirMount.FileSystem, "nfs") || strings.HasPrefix(srcDirMount.FileSystem, "cifs") {
		return fmt.Errorf(MSG_E_ENC_REMOTE_FS, srcDir)
	}

	// Look for SAP keywords among encryption paths
	encSAP := false
	sapKeywords := []string{"hana", "hdb", "sap", "sapdb", "sapmnt"}
	for _, seg := range strings.Split(srcDir, fmt.Sprintf("%c", os.PathSeparator)) {
		seg = strings.ToLower(seg)
		for _, kw := range sapKeywords {
			if kw == seg {
				encSAP = true
				break
			}
		}
	}
	if encSAP {
		// If encryption path touches SAP, make sure SAP keywords don't appear in the running process list.
		var seenSAPProc string
		walkErr := sys.WalkProcs(func(cmdLine []string) bool {
			for _, seg := range strings.Split(cmdLine[0], fmt.Sprintf("%c", os.PathSeparator)) {
				seg = strings.ToLower(seg)
				for _, kw := range sapKeywords {
					if kw == seg {
						seenSAPProc = strings.Join(cmdLine, " ")
						return false
					}
				}
			}
			return true
		})
		if walkErr != nil {
			return fmt.Errorf(MSG_E_WALK_PROC, walkErr)
		} else if seenSAPProc != "" {
			return fmt.Errorf(MSG_E_SAP_RUNNING, seenSAPProc)
		}
	}
	// Calculate size of files under the directory to encrypt
	encDiskDev, found := blkDevs.GetByCriteria("", encDisk, "", "", "")
	if !found {
		return fmt.Errorf(MSG_E_ENCRYPT_DISK_NOT_FOUND, encDisk)
	}
	dataSize, err := fs.FileSpaceUsage(srcDir)
	if err != nil {
		return fmt.Errorf(MSG_E_CALC_DIR_SIZE, srcDir, err)
	}
	// Make sure the disk to encrypt has enough capacity (leave 5% margin)
	minDiskSize := dataSize * 105 / 100
	if encDiskDev.SizeByte < minDiskSize {
		return fmt.Errorf(MSG_E_DISK_TOO_SMALL, encDisk, minDiskSize/1024/1024)
	}
	return nil
}

/*
Set up encryption on a file system using a randomly generated key and upload the key to key server. Return UUID of
now encrypted block device and any error encountered during the routine.
*/
func EncryptFS(progressOut io.Writer, client *keyrpc.CryptClient,
	password, srcDir, encDisk string,
	keyMaxActive, keyAliveIntervalSec, keyAliveCount int) (string, error) {
	sys.LockMem()
	srcDir = filepath.Clean(srcDir)
	encDisk = filepath.Clean(encDisk)

	// Step 0 - check pre-conditions for encryption and prompt user for confirmation
	err := EncryptFSPreCheck(srcDir, encDisk)
	if err != nil {
		return "", err
	}

	// Step 1. Un-mount the disk to encrypt
	fmt.Fprintf(progressOut, MSG_STEP_1, encDisk)
	mountPoints := fs.ParseMtab()
	for {
		// Repeat until the disk has no more mount points
		if mountPoint, found := mountPoints.GetByCriteria(encDisk, "", ""); found {
			if err := fs.Umount(mountPoint.MountPoint); err != nil {
				return "", err
			}
			mountPoints = fs.ParseMtab()
			continue
		}
		break
	}
	// Step 1 (cont). Wipe the disk and install encryption key
	encryptKey := make([]byte, fs.LUKS_KEY_SIZE_I)
	_, err = rand.Read(encryptKey)
	if err != nil {
		return "", fmt.Errorf(MSG_E_NO_RAND, err)

	}
	if err := fs.CryptFormat(encryptKey, encDisk); err != nil {
		return "", err
	}
	dmName := MakeDeviceMapperName(encDisk)
	if err := fs.CryptOpen(encryptKey, encDisk, dmName); err != nil {
		return "", err
	}
	srcDirMount, found := mountPoints.GetMountPointOfPath(srcDir)
	if !found {
		return "", fmt.Errorf(MSG_E_SRC_DIR_MOUNT_NOT_FOUND, srcDir)
	}
	encDiskMapper := path.Join("/dev/mapper", dmName)
	if err := fs.Format(encDiskMapper, srcDirMount.FileSystem); err != nil {
		return "", err
	}

	// Step 2. Copy data from directory to encrypt into the encrypted disk
	fmt.Fprintf(progressOut, MSG_STEP_2, srcDir)
	srcDirIsMountPoint := srcDirMount.MountPoint == srcDir
	srcDataDir := path.Join(path.Dir(srcDir), SRC_DIR_NEW_NAME_PREFIX+path.Base(srcDir))
	// Give the directory to encrypt a prefix name
	if srcDirIsMountPoint {
		// If the directory is a mount point, remount it into the new directory name.
		if err := fs.Umount(srcDir); err != nil {
			return "", err
		} else if err := os.MkdirAll(srcDataDir, 0700); err != nil {
			return "", fmt.Errorf(MSG_E_MKDIR, srcDataDir, err)
		} else if err := fs.Mount(srcDirMount.DeviceNode, srcDirMount.FileSystem, srcDirMount.Options, srcDataDir); err != nil {
			return "", err
		}
	} else {
		// If the directory is not a mount point, simply rename it.
		if err := os.Rename(srcDir, srcDataDir); err != nil {
			return "", fmt.Errorf(MSG_E_RENAME_DIR, srcDir, srcDataDir, err)
		} else if err := os.MkdirAll(srcDir, 0700); err != nil {
			return "", fmt.Errorf(MSG_E_MKDIR, srcDir, err)
		}
	}
	// From now on mount options will only be used to mount new encrypted file system, hence btrfs subvolume no longer makes sense.
	srcDirMount.DiscardBtrfsSubvolume()
	// Mount encrypted disk to srcDir and copy from newSrcDir to the now encrypted directory
	if err := fs.Mount(path.Join("/dev/mapper", dmName), srcDirMount.FileSystem, srcDirMount.Options, srcDir); err != nil {
		return "", err
	}
	if err := fs.MirrorFiles(srcDataDir, srcDir, progressOut); err != nil {
		return "", err
	}

	// Step 3. Announce the encrypted disk to key server.
	fmt.Fprintf(progressOut, MSG_STEP_3, client.ServerHost)
	cryptDev, found := fs.GetBlockDevice(encDisk)
	if !found {
		return "", fmt.Errorf(MSG_E_NO_DEV_INFO, encDisk)
	}
	keyRecord := keydb.Record{
		UUID:             cryptDev.UUID,
		Key:              encryptKey,
		MountPoint:       srcDir,
		MountOptions:     srcDirMount.Options,
		MaxActive:        keyMaxActive,
		AliveIntervalSec: keyAliveIntervalSec,
		AliveCount:       keyAliveCount,
	}
	if err := client.SaveKey(keyrpc.SaveKeyReq{
		Password: password,
		Record:   keyRecord,
	}); err != nil {
		return "", fmt.Errorf(MSG_E_RPC_KEY_SAVE, err)
	}
	fmt.Fprintf(progressOut, MSG_OK_CONGRATS, srcDir, encDisk, srcDataDir)
	return cryptDev.UUID, nil
}
