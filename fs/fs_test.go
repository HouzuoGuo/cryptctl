// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseBlockDevs(t *testing.T) {
	sample := `
UUID="" NAME="sda" TYPE="disk" FSTYPE="" MOUNTPOINT="" SIZE="42949672960" PKNAME=""
UUID="5719d731-61a1-485e-98c9-49969d66c210" NAME="sda1" TYPE="part" FSTYPE="ext4" MOUNTPOINT="/" SIZE="42943138304" PKNAME=""
UUID="68a72d63-b256-450e-b648-44782057153e" NAME="loop0" TYPE="loop" FSTYPE="crypto_LUKS" MOUNTPOINT="" SIZE="12582912000" PKNAME="loop0"
UUID="7d5ad550-8e81-45a9-895f-90bff713c63c" NAME="dm00" TYPE="crypt" FSTYPE="ext4" MOUNTPOINT="/home/howard" SIZE="12580814848" PKNAME="loop0"

UUID="" NAME="sr0" TYPE="rom" FSTYPE="" MOUNTPOINT="" SIZE="1073741312" PKNAME=""
UUID="" NAME="vda" TYPE="disk" FSTYPE="" MOUNTPOINT="" SIZE="68719476736" PKNAME=""

UUID="e3e82520-5123-490c-a01f-1b6226e770c2" NAME="vda1" TYPE="part" FSTYPE="swap" MOUNTPOINT="[SWAP]" SIZE="2153775104" PKNAME="loop0"
UUID="2a2e9ce7-6cd2-48ca-b932-37800eef51a2" NAME="vda2" TYPE="part" FSTYPE="xfs" MOUNTPOINT="/" SIZE="66564653056" PKNAME="loop0"
UUID="" NAME="vdb" TYPE="disk" FSTYPE="" MOUNTPOINT="" SIZE="8589934592" PKNAME="loop0"

UUID="9edcdeb9-86bd-4602-be5d-7a45a29fefc0" NAME="vdc" TYPE="disk" FSTYPE="crypto_LUKS" MOUNTPOINT="" SIZE="9663676416" PKNAME="loop0"
UUID="80c51aec-15e1-42ea-8520-1d6c707cd8e6" NAME="dm00" TYPE="crypt" FSTYPE="ext4" MOUNTPOINT="/mnt" SIZE="9661579264" PKNAME="loop0"
`
	ret := ParseBlockDevs(sample)
	expected := BlockDevices{
		BlockDevice{UUID: "", Path: "/dev/sda", Type: "disk", FileSystem: "", MountPoint: "", SizeByte: 42949672960, PKName: "", Name: "sda"},
		BlockDevice{UUID: "5719d731-61a1-485e-98c9-49969d66c210", Path: "/dev/sda1", Type: "part", FileSystem: "ext4", MountPoint: "/", SizeByte: 42943138304, PKName: "", Name: "sda1"},
		BlockDevice{UUID: "68a72d63-b256-450e-b648-44782057153e", Path: "/dev/loop0", Type: "loop", FileSystem: "crypto_LUKS", MountPoint: "", SizeByte: 12582912000, PKName: "loop0", Name: "loop0"},
		BlockDevice{UUID: "7d5ad550-8e81-45a9-895f-90bff713c63c", Path: "/dev/mapper/dm00", Type: "crypt", FileSystem: "ext4", MountPoint: "/home/howard", SizeByte: 12580814848, PKName: "loop0", Name: "dm00"},

		BlockDevice{UUID: "", Path: "/dev/sr0", Type: "rom", FileSystem: "", MountPoint: "", SizeByte: 1073741312, PKName: "", Name: "sr0"},
		BlockDevice{UUID: "", Path: "/dev/vda", Type: "disk", FileSystem: "", MountPoint: "", SizeByte: 68719476736, PKName: "", Name: "vda"},

		BlockDevice{UUID: "e3e82520-5123-490c-a01f-1b6226e770c2", Path: "/dev/vda1", Type: "part", FileSystem: "swap", MountPoint: "[SWAP]", SizeByte: 2153775104, PKName: "loop0", Name: "vda1"},
		BlockDevice{UUID: "2a2e9ce7-6cd2-48ca-b932-37800eef51a2", Path: "/dev/vda2", Type: "part", FileSystem: "xfs", MountPoint: "/", SizeByte: 66564653056, PKName: "loop0", Name: "vda2"},
		BlockDevice{UUID: "", Path: "/dev/vdb", Type: "disk", FileSystem: "", MountPoint: "", SizeByte: 8589934592, PKName: "loop0", Name: "vdb"},

		BlockDevice{UUID: "9edcdeb9-86bd-4602-be5d-7a45a29fefc0", Path: "/dev/vdc", Type: "disk", FileSystem: "crypto_LUKS", MountPoint: "", SizeByte: 9663676416, PKName: "loop0", Name: "vdc"},
		BlockDevice{UUID: "80c51aec-15e1-42ea-8520-1d6c707cd8e6", Path: "/dev/mapper/dm00", Type: "crypt", FileSystem: "ext4", MountPoint: "/mnt", SizeByte: 9661579264, PKName: "loop0", Name: "dm00"},
	}
	if !reflect.DeepEqual(ret, expected) {
		for i, _ := range ret {
			if !reflect.DeepEqual(ret[i], expected[i]) {
				fmt.Printf("%+v\n", ret[i])
				fmt.Printf("%+v\n", expected[i])
			}
		}
		t.Fatalf("mismatch\n%+v\n%+v\n", ret, expected)
	}

	if dev, err := ret.GetByCriteria("", "/dev/sda1", "", "", "", "", ""); dev != expected[1] {
		t.Fatal(dev, err)
	}
	if dev, err := ret.GetByCriteria("", "", "loop", "", "", "", ""); dev != expected[2] {
		t.Fatal(dev, err)
	}
	if dev, err := ret.GetByCriteria("", "/dev/mapper/dm00", "", "ext4", "", "", ""); dev != expected[3] {
		t.Fatal(dev, err)
	}
	if dev, err := ret.GetByCriteria("", "", "", "", "[SWAP]", "", ""); dev != expected[6] {
		t.Fatal(dev, err)
	}
	if dev, err := ret.GetByCriteria("80c51aec-15e1-42ea-8520-1d6c707cd8e6", "/dev/mapper/dm00", "crypt", "ext4", "/mnt", "loop0", "dm00"); dev != expected[10] {
		t.Fatal(dev, err)
	}
	if expected[8].IsLUKSEncrypted() {
		t.Fatal("encrypted - wrong")
	}
	if !expected[9].IsLUKSEncrypted() {
		t.Fatal("not encrypted - wrong")
	}
}

func TestGetBlockDevices(t *testing.T) {
	devs := GetBlockDevices()
	if len(devs) == 0 {
		t.Fatal("did not get any block devs")
	}
	if err := CheckBlockDevice(devs[0].Path); err != nil {
		t.Fatal(err)
	} else if err := CheckBlockDevice("/dev/does not exist"); err == nil {
		t.Fatal("did not error")
	}
	if blk0, found := GetBlockDevice(devs[0].Path); !found || !reflect.DeepEqual(blk0, devs[0]) {
		t.Fatal(blk0, found)
	}
	if blk1, found := GetBlockDevice("does not exist"); found {
		t.Fatal(blk1, found)
	}
}

func TestFormat(t *testing.T) {
	if err := Format("/dev/does not exist", "ext4"); err == nil {
		t.Fatal("did not error")
	}
}

func TestFreeSpace(t *testing.T) {
	if size, err := FreeSpace("/etc/os-release"); err != nil || size < 3 {
		t.Fatal(err, size)
	}
}

func TestGetSystemdMountNameForDir(t *testing.T) {
	in := `/root/a-b c!@`
	out := `root-a\x2db\x20c\x21\x40.mount`
	if ret := GetSystemdMountNameForDir(in); ret != out {
		t.Fatal(ret)
	}
}
