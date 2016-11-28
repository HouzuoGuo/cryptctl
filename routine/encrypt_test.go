// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/keyrpc"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPreCheck(t *testing.T) {
	rootDev, found := fs.GetBlockDevices().GetByCriteria("", "", "", "", "/")
	if !found {
		t.Fatal("cannot find root's device")
	}
	// Input paths should exist
	if err := EncryptFSPreCheck("/does_not_exist", rootDev.Path); err == nil {
		t.Fatal("did not error")
	}
	if err := EncryptFSPreCheck("/etc/security", "/dev/does_not_exist"); err == nil {
		t.Fatal("did not error")
	}
	// There must not be other mount points under the directory to encrypt
	if err := EncryptFSPreCheck("/", rootDev.Path); err == nil {
		t.Fatal("did not error")
	}
	// The directory to encrypt must not be a mount point from the disk to encrypt
	if err := EncryptFSPreCheck("/etc", rootDev.Path); err == nil {
		t.Fatal("did not error")
	}
}

// Comprehensive integration test for encryption/unlocking routine. This test case requires root privilege to run.
func TestEncryptDecrypt(t *testing.T) {
	osSignal := make(chan os.Signal, 1)
	signal.Notify(osSignal, syscall.SIGQUIT)
	go func() {
		for {
			<-osSignal
			outBuf := make([]byte, 2048)
			for {
				// Keep re-collecting stack traces until the buffer is large enough to hold all of them
				sizeWritten := runtime.Stack(outBuf, false)
				if len(outBuf) >= sizeWritten {
					fmt.Fprint(os.Stderr, string(outBuf))
					break
				}
				outBuf = make([]byte, 2*len(outBuf))
			}
		}
	}()

	if os.Getuid() != 0 {
		t.Skip("This test case requires root privilege to run")
	}
	// Start an RPC server
	keydbDir := "/tmp/cryptctl-encrypttest"
	os.RemoveAll(keydbDir)
	defer os.RemoveAll(keydbDir)
	salt := keyrpc.NewSalt()
	passHash := keyrpc.HashPassword(salt, keyrpc.TEST_RPC_PASS)
	sysconf := keyrpc.GetDefaultKeySvcConf()
	sysconf.Set(keyrpc.SRV_CONF_KEYDB_DIR, keydbDir)
	sysconf.Set(keyrpc.SRV_CONF_TLS_CERT, path.Join(keyrpc.PkgInGopath, "keyrpc", "rpc_test.crt"))
	sysconf.Set(keyrpc.SRV_CONF_TLS_KEY, path.Join(keyrpc.PkgInGopath, "keyrpc", "rpc_test.key"))
	sysconf.Set(keyrpc.SRV_CONF_PASS_SALT, hex.EncodeToString(salt[:]))
	sysconf.Set(keyrpc.SRV_CONF_PASS_HASH, hex.EncodeToString(passHash[:]))
	// To test email notification, simply start postfix at its default configuration
	// You should receive four emails - two for key creation, two for key retrieval
	// The emails are delivered to both user root and howard
	sysconf.Set(keyrpc.SRV_CONF_MAIL_AGENT_AND_PORT, "localhost:25")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_FROM_ADDR, "cryptctl@localhost")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_RECIPIENTS, "root@localhost howard@localhost")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_CREATION_SUBJ, "key was created")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_CREATION_TEXT, "look out he's got a key")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_RETRIEVAL_SUBJ, "key was retrieved")
	sysconf.Set(keyrpc.SRV_CONF_MAIL_RETRIEVAL_TEXT, "look out he's got a key again")
	srvConf := keyrpc.CryptServiceConfig{}
	srvConf.ReadFromSysconfig(sysconf)
	mailer := keyrpc.Mailer{}
	mailer.ReadFromSysconfig(sysconf)
	if err := mailer.ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	srv, err := keyrpc.NewCryptServer(srvConf, mailer)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		srv.ListenRPC()
	}()
	// Make an RPC client
	time.Sleep(2 * time.Second)
	certContent, err := ioutil.ReadFile(path.Join(keyrpc.PkgInGopath, "keyrpc", "rpc_test.crt"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := keyrpc.NewCryptClient("localhost", 3737, certContent)
	if err != nil {
		t.Fatal(err)
	}

	// Set up two directories to encrypt (one of which is a mount point), and two disks to encrypt
	os.RemoveAll("/cryptctl-encrypttest")
	srcDir0 := "/cryptctl-encrypttest/secret0"
	srcDir1 := "/cryptctl-encrypttest/secret1"
	movedSrcDir0 := "/cryptctl-encrypttest/" + SRC_DIR_NEW_NAME_PREFIX + "secret0"
	movedSrcDir1 := "/cryptctl-encrypttest/" + SRC_DIR_NEW_NAME_PREFIX + "secret1"
	loDisk0 := "/cryptctl-encrypttest/disk0"
	loDisk1 := "/cryptctl-encrypttest/disk1"
	loDiskSrc1 := "/cryptctl-encrypttest/disk-src1"
	loop0Crypt := MakeDeviceMapperName("/dev/loop0")
	loop1Crypt := MakeDeviceMapperName("/dev/loop1")
	loop0Mount, err := ioutil.TempDir("", "cryptctl-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Clean up!
		if err := fs.Umount(srcDir1); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := fs.Umount(movedSrcDir1); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := fs.CryptClose(loop1Crypt); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		if err := fs.Umount(srcDir0); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := fs.Umount(movedSrcDir0); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := fs.CryptClose(loop0Crypt); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := fs.Umount(loop0Mount); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		// There are in total three loop disks to destroy
		for i := 0; i < 3; i++ {
			if _, _, _, err := sys.Exec(nil, nil, nil, "/usr/sbin/losetup", "-D"); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		if err := os.RemoveAll(loop0Mount); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := os.RemoveAll("/cryptctl-encrypttest"); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	if err := os.MkdirAll(srcDir0, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcDir1, 0755); err != nil {
		t.Fatal(err)
	}
	// Set up loop disks
	if err := ioutil.WriteFile(loDisk0, bytes.Repeat([]byte{0}, 10*1048576), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(loDisk1, bytes.Repeat([]byte{0}, 10*1048576), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(loDiskSrc1, bytes.Repeat([]byte{0}, 10*1048576), 0600); err != nil {
		t.Fatal(err)
	}
	if status, stdout, stderr, err := sys.Exec(nil, nil, nil, "/usr/sbin/losetup", "-f", loDisk0); err != nil {
		t.Fatal(status, err, stdout, stderr)
	}
	if status, stdout, stderr, err := sys.Exec(nil, nil, nil, "/usr/sbin/losetup", "-f", loDisk1); err != nil {
		t.Fatal(status, err, stdout, stderr)
	}
	if status, stdout, stderr, err := sys.Exec(nil, nil, nil, "/usr/sbin/losetup", "-f", loDiskSrc1); err != nil {
		t.Fatal(status, err, stdout, stderr)
	}
	// Format and mount disk-src1 (loop2) to secret1
	if err := fs.Format("/dev/loop2", "ext4"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mount("/dev/loop2", "ext4", []string{}, srcDir1); err != nil {
		t.Fatal(err)
	}
	// Mount encrypt disk 0 (loop0) to a temporary location so that encryption routine will have to umount it
	if err := fs.Format("/dev/loop0", "ext4"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mount("/dev/loop0", "ext4", []string{}, loop0Mount); err != nil {
		t.Fatal(err)
	}

	// Create some sample files and directories to encrypt
	if err := os.MkdirAll(path.Join(srcDir0, "a/b"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(srcDir0, "a/b/0"), []byte{0}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path.Join(srcDir1, "c/d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(srcDir1, "c/d/1"), []byte{1}, 0644); err != nil {
		t.Fatal(err)
	}

	/*
		===============================================
		Encrypt new disks
		===============================================
	*/
	var encUUID0, encUUID1 string
	// Run encryption routine on two directories + two disks
	// The first disk can be unlocked twice at the same time
	encUUID0, err = EncryptFS(os.Stdout, client, keyrpc.TEST_RPC_PASS, srcDir0, "/dev/loop0", 2, REPORT_ALIVE_INTERVAL_SEC, 2)
	if err != nil || encUUID0 == "" {
		t.Fatal(err, encUUID0)
	}
	//The second disk can only be unlocked once.
	encUUID1, err = EncryptFS(os.Stdout, client, keyrpc.TEST_RPC_PASS, srcDir1, "/dev/loop1", 1, REPORT_ALIVE_INTERVAL_SEC, 2)
	if err != nil || encUUID1 == "" {
		t.Fatal(err, encUUID1)
	}

	// Check encryption setup on secret0
	checkSecret0 := func() {
		if st, err := fs.CryptStatus(loop0Crypt); err != nil || st.Device != "/dev/loop0" ||
			st.KeySize != fs.LUKS_KEY_SIZE_I || st.Cipher != fs.LUKS_CIPHER || st.Loop != "/cryptctl-encrypttest/disk0" {
			log.Panicf("%+v %+v", err, st)
		}
		if blk, found := fs.GetBlockDevice(path.Join("/dev/mapper/", loop0Crypt)); !found || blk.MountPoint != srcDir0 {
			log.Panic(found, blk)
		}
		if txt, err := ioutil.ReadFile(path.Join(srcDir0, "a/b/0")); err != nil || len(txt) != 1 || txt[0] != 0 {
			log.Panic(err, txt)
		}
		if txt, err := ioutil.ReadFile(path.Join(movedSrcDir0, "a/b/0")); err != nil || len(txt) != 1 || txt[0] != 0 {
			log.Panic(err, txt)
		}
	}
	checkSecret0()

	// Check encryption setup on secret1
	checkSecret1 := func() {
		if st, err := fs.CryptStatus(loop1Crypt); err != nil || st.Device != "/dev/loop1" {
			log.Panicf("%+v %+v", err, st)
		}
		if blk, found := fs.GetBlockDevice(path.Join("/dev/mapper/", loop1Crypt)); !found || blk.MountPoint != srcDir1 {
			log.Panic(found, blk)
		}
		if txt, err := ioutil.ReadFile(path.Join(srcDir1, "c/d/1")); err != nil || len(txt) != 1 || txt[0] != 1 {
			log.Panic(err, txt)
		}
		if txt, err := ioutil.ReadFile(path.Join(movedSrcDir1, "c/d/1")); err != nil || len(txt) != 1 || txt[0] != 1 {
			log.Panic(err, txt)
		}
	}
	checkSecret1()

	// Reset disks to emulate a clean reboot
	resetDisks := func() {
		if err := fs.Umount(srcDir0); err != nil {
			t.Fatal(err)
		}
		if err := fs.Umount(srcDir1); err != nil {
			t.Fatal(err)
		}
		if err := fs.CryptClose(loop0Crypt); err != nil {
			t.Fatal(err)
		}
		if err := fs.CryptClose(loop1Crypt); err != nil {
			t.Fatal(err)
		}
	}

	/*
		===============================================
		Forcibly unlock all disks via password
		===============================================
	*/
	resetDisks()
	// Unlock disks with password
	if err := ManOnlineUnlockFS(os.Stdout, client, keyrpc.TEST_RPC_PASS); err != nil {
		t.Fatal(err)
	}
	checkSecret0()
	checkSecret1()

	// Shut down the server, start it once more and try unlocking the disks.
	resetDisks()
	if err := client.Shutdown(keyrpc.ShutdownReq{Challenge: srv.ShutdownChallenge}); err != nil {
		t.Fatal(err)
	}
	srv, err = keyrpc.NewCryptServer(srvConf, mailer)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		srv.ListenRPC()
	}()

	// There's no need to make a new RPC client because the client does not hold a persistent connection
	if err := ManOnlineUnlockFS(os.Stdout, client, keyrpc.TEST_RPC_PASS); err != nil {
		t.Fatal(err)
	}
	checkSecret0()
	checkSecret1()

	/*
		===============================================
		Automatically unlock disk without password
		Send alive messages
		===============================================
	*/
	resetDisks()
	blkDevs := fs.GetBlockDevices()
	loop0Dev, found := blkDevs.GetByCriteria("", "/dev/loop0", "", "", "")
	if !found || !loop0Dev.IsLUKSEncrypted() {
		t.Fatal(loop0Dev)
	}
	if loop0Dev.UUID != encUUID0 {
		t.Fatal(loop0Dev.UUID, encUUID0)
	}
	loop1Dev, found := blkDevs.GetByCriteria("", "/dev/loop1", "", "", "")
	if !found || !loop1Dev.IsLUKSEncrypted() {
		t.Fatal(loop1Dev)
	}
	if loop1Dev.UUID != encUUID1 {
		t.Fatal(loop1Dev.UUID, encUUID1)
	}
	// Temporarily shut down server while requesting to unlock disks via automated method (not manual method)
	if err := client.Shutdown(keyrpc.ShutdownReq{Challenge: srv.ShutdownChallenge}); err != nil {
		t.Fatal(err)
	}
	// Six unlock attempts will be made against different disks
	onlineUnlockAttempt := make([]chan error, 5)
	for i := 0; i < 5; i++ {
		onlineUnlockAttempt[i] = make(chan error, 1)
	}
	// First two attempts are made against loop0, both attempts should succeed.
	reportAliveMayEnd := false // when it is time for ReportAlive to end, this flag will become true.
	finishedReportAlive := new(sync.WaitGroup)
	finishedReportAlive.Add(3) // two for loop0, one for loop1.
	for i := 0; i < 2; i++ {
		go func(i int) {
			err := AutoOnlineUnlockFS(os.Stdout, client, loop0Dev.UUID, REPORT_ALIVE_INTERVAL_SEC*2)
			// Once key is retrieved successfully, begin sending alive messages.
			if err == nil {
				go func() {
					if aliveErr := ReportAlive(os.Stdout, client, loop0Dev.UUID); aliveErr != nil && !reportAliveMayEnd {
						t.Log(aliveErr)
					} else {
						finishedReportAlive.Done()
					}
				}()
			}
			onlineUnlockAttempt[i] <- err
		}(i)
	}
	// Next two attempts are made against loop1 that only allows one active user. Only one attempt should succeed.
	for i := 2; i < 4; i++ {
		go func(i int) {
			err := AutoOnlineUnlockFS(os.Stdout, client, loop1Dev.UUID, REPORT_ALIVE_INTERVAL_SEC*2)
			// Once key is retrieved successfully, begin sending alive messages.
			if err == nil {
				go func() {
					if aliveErr := ReportAlive(os.Stdout, client, loop1Dev.UUID); aliveErr != nil && !reportAliveMayEnd {
						t.Log(aliveErr)
					} else {
						finishedReportAlive.Done()
					}
				}()
			}
			onlineUnlockAttempt[i] <- err
		}(i)
	}
	// The second last attempt is made against a disk that does not have key on the server.
	go func() {
		onlineUnlockAttempt[4] <- AutoOnlineUnlockFS(os.Stdout, client, "this-uuid-does-not-exist", 15)
	}()

	// Bring server online now
	srv, err = keyrpc.NewCryptServer(srvConf, mailer)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		srv.ListenRPC()
	}()
	// Check result from each unlock attempt
	onlineUnlockErr := make([]error, 5)
	for i := 0; i < 5; i++ {
		onlineUnlockErr[i] = <-onlineUnlockAttempt[i]
	}
	if onlineUnlockErr[0] != nil || onlineUnlockErr[1] != nil {
		// both of of loop0's attempts shall succeed
		t.Fatal(loop0Dev.UUID, onlineUnlockErr[0], onlineUnlockErr[1])
	} else if (onlineUnlockErr[2] == nil) == (onlineUnlockErr[3] == nil) {
		// one of loop1's attempt shall succeed
		t.Fatal(loop1Dev.UUID, onlineUnlockErr[2], onlineUnlockErr[3])
	} else if onlineUnlockErr[4] == nil {
		t.Fatal("did not error")
	}
	checkSecret0()
	checkSecret1()
	// Alive messages should have been sent by ReportAlive
	if msgs := srv.KeyDB.Records[loop0Dev.UUID].AliveMessages["127.0.0.1"]; len(msgs) == 0 {
		t.Fatal(msgs)
	}
	// Sending alive message to non-existing reports should result in immediate rejection
	if ReportAlive(os.Stdout, client, "this-uuid-does-not-exist") == nil {
		t.Fatal("did not error")
	}
	/*
		Put two other hosts into records' alive message history so that the ReportAlive RPC messages will be rejected,
		and their goroutines will end.
	*/
	srv.KeyDB.Lock.Lock()
	id0Record := srv.KeyDB.Records[encUUID0]
	id0Record.AliveMessages = map[string][]keydb.AliveMessage{
		"NewHost1": []keydb.AliveMessage{
			{
				Hostname:  "NewHost1",
				IP:        "1.1.1.1",
				Timestamp: time.Now().Unix(),
			},
		},
		"NewHost2": []keydb.AliveMessage{
			{
				Hostname:  "NewHost2",
				IP:        "1.1.1.2",
				Timestamp: time.Now().Unix(),
			},
		}}
	srv.KeyDB.Records[encUUID0] = id0Record
	id1Record := srv.KeyDB.Records[encUUID1]
	id1Record.AliveMessages = map[string][]keydb.AliveMessage{
		"NewHost1": []keydb.AliveMessage{
			{
				Hostname:  "NewHost1",
				IP:        "1.1.1.1",
				Timestamp: time.Now().Unix(),
			},
		},
		"NewHost2": []keydb.AliveMessage{
			{
				Hostname:  "NewHost2",
				IP:        "1.1.1.2",
				Timestamp: time.Now().Unix(),
			},
		}}
	srv.KeyDB.Records[encUUID1] = id1Record
	srv.KeyDB.Lock.Unlock()
	reportAliveMayEnd = true
	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	fmt.Println("The ReportAlive goroutines should soon end. If the test case does not progress further, it is failed.")
	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	finishedReportAlive.Wait()
	checkSecret0()
	checkSecret1()

	/*
		===============================================
		Unlock a disk via record file
		===============================================
	*/
	resetDisks()
	// Now that server has shut down, try to unlock disks using key records only.
	if len(srv.KeyDB.Records) != 2 {
		t.Fatal(srv.KeyDB.Records)
	}
	records := make([]keydb.Record, 0, 0)
	for _, record := range srv.KeyDB.Records {
		records = append(records, record)
		fmt.Println("Offline-unlocking", record.MountPoint, record.UUID)
		if err := UnlockFS(os.Stdout, record); err != nil {
			t.Fatal(err)
		}
	}
	if len(records) != 2 {
		t.Fatal(records)
	}
	// Unlock a disk that does not exist should not do any harm
	bogusRecord := keydb.Record{
		UUID:         "this-uuid-is-totally-bogus",
		Key:          []byte{0, 1, 2},
		MountPoint:   "/tmp",
		MountOptions: []string{},
	}
	if err := UnlockFS(os.Stdout, bogusRecord); err == nil {
		t.Fatal("did not error")
	}
	checkSecret0()
	checkSecret1()

	/*
		===============================================
		Erase both encryption keys while they are mounted
		===============================================
	*/
	// First attempt erases an open & mounted file system
	if err := EraseKey(os.Stdout, client, keyrpc.TEST_RPC_PASS, encUUID0); err != nil {
		t.Fatal(err)
	}
	// Second attempt erases a not yet mounted file system
	if err := fs.Umount(srcDir1); err != nil {
		t.Fatal(err)
	}
	if err := fs.CryptClose(loop1Crypt); err != nil {
		t.Fatal(err)
	}
	if err := EraseKey(os.Stdout, client, keyrpc.TEST_RPC_PASS, encUUID1); err != nil {
		t.Fatal(err)
	}
	if len(srv.KeyDB.Records) != 0 {
		t.Fatal(srv.KeyDB.Records)
	}
	// Both file systems should now be crypto-closed
	if _, err := fs.CryptStatus(loop0Crypt); err == nil {
		t.Fatal("did not close")
	}
	if _, found := fs.GetBlockDevice(path.Join("/dev/mapper/", loop0Crypt)); found {
		fmt.Println("did not close!!")
		time.Sleep(30 * time.Second)
		t.Fatal("did not close")
	}
	if _, err := ioutil.ReadFile(path.Join(srcDir0, "a/b/0")); err == nil {
		t.Fatal("did not umount")
	}
	if _, err := fs.CryptStatus(loop1Crypt); err == nil {
		t.Fatal("did not close")
	}
	if _, found := fs.GetBlockDevice(path.Join("/dev/mapper/", loop1Crypt)); found {
		t.Fatal("did not close")
	}
	if _, err := ioutil.ReadFile(path.Join(srcDir1, "c/d/1")); err == nil {
		t.Fatal("did not umount")
	}

	// Now those records won't be able to unlock disks anymore
	if err := UnlockFS(os.Stdout, records[0]); err == nil {
		t.Fatal("did not error")
	}
	if err := UnlockFS(os.Stdout, records[1]); err == nil {
		t.Fatal("did not error")
	}

	if err := client.Shutdown(keyrpc.ShutdownReq{Challenge: srv.ShutdownChallenge}); err != nil {
		t.Fatal(err)
	}
}
