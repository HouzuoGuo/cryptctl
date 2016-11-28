// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import (
	"reflect"
	"testing"
)

var procMountsSample = `
# SLES 11
rootfs / rootfs rw 0 0
udev /dev tmpfs rw,relatime,nr_inodes=0,mode=755 0 0
tmpfs /dev/shm tmpfs rw,relatime,size=8388608k 0 0
/dev/vda2 / ext3 rw,relatime,errors=continue,user_xattr,acl,barrier=1,data=ordered 0 0
proc /proc proc rw,relatime 0 0
sysfs /sys sysfs rw,relatime 0 0
devpts /dev/pts devpts rw,relatime,gid=5,mode=620,ptmxmode=000 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
securityfs /sys/kernel/security securityfs rw,relatime 0 0
gvfs-fuse-daemon /root/.gvfs fuse.gvfs-fuse-daemon rw,nosuid,nodev,relatime,user_id=0,group_id=0 0 0

# SLES 12
rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4086316k,nr_inodes=1021579,mode=755 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,size=8388608k 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpuacct,cpu 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
/dev/vda2 / ext4 rw,relatime,data=ordered 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=28,pgrp=1,timeout=300,minproto=5,maxproto=5,direct 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,relatime 0 0
mqueue /dev/mqueue mqueue rw,relatime 0 0
gvfsd-fuse /run/user/0/gvfs fuse.gvfsd-fuse rw,nosuid,nodev,relatime,user_id=0,group_id=0 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0

# SLES 12 SAP
rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4086164k,nr_inodes=1021541,mode=755 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,size=8388608k 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpuacct,cpu 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
/dev/vda2 / ext4 rw,relatime,data=ordered 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=31,pgrp=1,timeout=300,minproto=5,maxproto=5,direct 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
mqueue /dev/mqueue mqueue rw,relatime 0 0
gvfsd-fuse /run/user/0/gvfs fuse.gvfsd-fuse rw,nosuid,nodev,relatime,user_id=0,group_id=0 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0

# Tumbleweed
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=16427624k,nr_inodes=4106906,mode=755 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,size=5120000k 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
/dev/sda1 / ext4 rw,relatime,data=ordered 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=25,pgrp=1,timeout=0,minproto=5,maxproto=5,direct 0 0
mqueue /dev/mqueue mqueue rw,relatime 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
tmpfs /var/run tmpfs rw,nosuid,nodev,mode=755 0 0
/dev/sdb1 /mass ext4 rw,relatime,data=ordered 0 0
tmpfs /run/user/0 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700 0 0
tmpfs /var/run/user/0 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700 0 0
tmpfs /run/user/472 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700,uid=472,gid=474 0 0
tmpfs /var/run/user/472 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700,uid=472,gid=474 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700,uid=1000,gid=100 0 0
tmpfs /var/run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=3286976k,mode=700,uid=1000,gid=100 0 0
gvfsd-fuse /run/user/1000/gvfs fuse.gvfsd-fuse rw,nosuid,nodev,relatime,user_id=1000,group_id=100 0 0
gvfsd-fuse /var/run/user/1000/gvfs fuse.gvfsd-fuse rw,nosuid,nodev,relatime,user_id=1000,group_id=100 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
tracefs /sys/kernel/debug/tracing tracefs rw,relatime 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw,relatime 0 0
`

func TestParseMounts(t *testing.T) {
	// source from /proc/mounts
	mountPoints := ParseMountPoints(procMountsSample)
	// rootfs is discarded
	if len(mountPoints) != 98 {
		t.Fatal(len(mountPoints))
	}
	for _, mount := range mountPoints {
		if mount.DeviceNode == "" || mount.MountPoint == "" || len(mount.Options) < 1 || mount.FileSystem == "" {
			t.Fatal(mount)
		}
	}
	shmMount := MountPoint{
		DeviceNode: "tmpfs",
		MountPoint: "/dev/shm",
		FileSystem: "tmpfs",
		Options:    []string{"rw", "relatime", "size=8388608k"},
		Dump:       0,
		Fsck:       0,
	}
	if mount, found := mountPoints.GetByCriteria("", "/dev/shm", ""); !found || !mount.Equals(shmMount) {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetByCriteria("tmpfs", "", ""); !found || !mount.Equals(shmMount) {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetByCriteria("", "", "tmpfs"); !found || !mount.Equals(mountPoints[0]) {
		// udev
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetByCriteria("tmpfs", "/dev/shm", "tmpfs"); !found || !mount.Equals(shmMount) {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetByCriteria("", "/doesnotexist", ""); found || mount.MountPoint != "" {
		t.Fatal(mount, found)
	}
}

func TestMountPointGetFileSystemSizeMB(t *testing.T) {
	mountPoints := ParseMtab()
	mount, found := mountPoints.GetByCriteria("", "/", "")
	if !found {
		t.Fatal(mount, found)
	}
	if size, err := mount.GetFileSystemSizeByte(); err != nil || size < 3000 {
		t.Fatal(err, size)
	}
}

func TestGetMountPointOf(t *testing.T) {
	var sample = `
cgroup /a cgroup rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
/dev/vda2 /simpleext4 ext4 rw,relatime,data=ordered 0 0
mqueue /a/b mqueue rw,relatime 0 0
fusectl /c/d fusectl rw,relatime 0 0
/dev/mapper/system-root /e btrfs rw 0 0
sysfs /f/g/h sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/important /important1 ext4 rw,nosuid,nodev,noexec,relatime 0 0
/dev/important /important1/a ext4 rw,nosuid,nodev,noexec,relatime 0 0
/dev/important /important2 ext4 rw,nosuid,nodev,noexec,relatime 0 0
rootfs / rootfs rw 0 0
/dev/mapper/system-root / btrfs rw,relatime,space_cache,subvolid=259,subvol=/@/.snapshots/1/snapshot 0 0
/dev/mapper/system-root /.snapshots btrfs rw,relatime,space_cache,subvolid=258,subvol=/@/.snapshots 0 0
/dev/mapper/system-root /var/opt btrfs rw,relatime,space_cache,subvolid=275,subvol=/@/var/opt 0 0
/dev/mapper/cryptctl-unlocked-vdc /sap btrfs rw,relatime,space_cache,subvolid=5,subvol=/ 0 0
/dev/mapper/cryptctl-unlocked-vdd /localsap btrfs rw,relatime,space_cache,subvolid=5,subvol=/ 0 0
/dev/mapper/system-root /var/lib/libvirt/images btrfs rw,relatime,space_cache,subvolid=268,subvol=/@/var/lib/libvirt/images 0 0

`
	mountPoints := ParseMountPoints(sample)
	// rootfs is discarded
	if len(mountPoints) != 15 {
		t.Fatal(len(mountPoints))
	}

	if mount, found := mountPoints.GetMountPointOfPath("/whatever"); !mount.Equals(mountPoints[9]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/a/c"); !mount.Equals(mountPoints[0]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/a"); !mount.Equals(mountPoints[0]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/"); !mount.Equals(mountPoints[9]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/a/b/c"); !mount.Equals(mountPoints[2]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/c/d/e/f/g"); !mount.Equals(mountPoints[3]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/e"); !mount.Equals(mountPoints[4]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/f/g"); !mount.Equals(mountPoints[9]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/f/g/h"); !mount.Equals(mountPoints[5]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/f/g/h/i"); !mount.Equals(mountPoints[5]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/important1/b"); !mount.Equals(mountPoints[6]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/important1/a"); !mount.Equals(mountPoints[7]) || !found {
		t.Fatal(mount, found)
	}
	if mount, found := mountPoints.GetMountPointOfPath("/important2/a"); !mount.Equals(mountPoints[8]) || !found {
		t.Fatal(mount, found)
	}

	match := MountPoints{mountPoints[6], mountPoints[7], mountPoints[8]}
	if points := mountPoints.GetManyByCriteria("/dev/important", "", ""); len(points) != 3 || !reflect.DeepEqual(points, match) {
		t.Fatal(points)
	}
}

func TestDiscardBtrfsSubvolume(t *testing.T) {
	var sample = `
/dev/mapper/system-root / btrfs rw,relatime,space_cache,subvolid=259,subvol=/@/.snapshots/1/snapshot 0 0
/dev/mapper/system-root /.snapshots btrfs rw,relatime,space_cache,subvolid=258,subvol=/@/.snapshots 0 0
/dev/mapper/system-root /var/opt btrfs rw,relatime,space_cache,subvolid=275,subvol=/@/var/opt 0 0
/dev/mapper/cryptctl-unlocked-vdc /sap btrfs rw,relatime,space_cache,subvolid=5,subvol=/ 0 0
`
	mountPoints := ParseMountPoints(sample)
	mountPoints[0].DiscardBtrfsSubvolume()
	if !reflect.DeepEqual(mountPoints[0].Options, []string{"rw", "relatime", "space_cache"}) {
		t.Fatal(mountPoints[0])
	}
	mountPoints[1].DiscardBtrfsSubvolume()
	if !reflect.DeepEqual(mountPoints[1].Options, []string{"rw", "relatime", "space_cache"}) {
		t.Fatal(mountPoints[1])
	}
	mountPoints[2].DiscardBtrfsSubvolume()
	if !reflect.DeepEqual(mountPoints[2].Options, []string{"rw", "relatime", "space_cache"}) {
		t.Fatal(mountPoints[2])
	}
	mountPoints[3].DiscardBtrfsSubvolume()
	if !reflect.DeepEqual(mountPoints[3].Options, []string{"rw", "relatime", "space_cache"}) {
		t.Fatal(mountPoints[3])
	}
}
