// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"fmt"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/sys"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCreateKeyReq_Validate(t *testing.T) {
	req := CreateKeyReq{}
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "UUID must not be empty") {
		t.Fatal(err)
	}
	req.UUID = "/root/../a-"
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal chara") {
		t.Fatal(err)
	}
	req.UUID = "abc-def-123-ghi"
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "Mount point") {
		t.Fatal(err)
	}
	req.MountPoint = "/a"
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRPCCalls(t *testing.T) {
	client, tearDown := StartTestServer(t)
	defer tearDown(t)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(PingRequest{Password: HashPassword(salt, "wrong password")}); err == nil {
		t.Fatal("did not error")
	}
	if err := client.Ping(PingRequest{Password: HashPassword(salt, TEST_RPC_PASS)}); err != nil {
		t.Fatal(err)
	}
	// Construct a client via sysconfig
	scClientConf, _ := sys.ParseSysconfig("")
	scClientConf.Set(CLIENT_CONF_HOST, "localhost")
	scClientConf.Set(CLIENT_CONF_PORT, strconv.Itoa(SRV_DEFAULT_PORT))
	scClientConf.Set(CLIENT_CONF_CA, path.Join(PkgInGopath, "keyserv", "rpc_test.crt"))
	scClient, err := NewCryptClientFromSysconfig(scClientConf)
	if err != nil {
		t.Fatal(err)
	}
	if err := scClient.Ping(PingRequest{Password: HashPassword(salt, TEST_RPC_PASS)}); err != nil {
		t.Fatal(err)
	}
	// Refuse to save a key if password is incorrect
	createResp, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, "wrong password"),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	})
	if err == nil {
		t.Fatal("did not error")
	}
	// Save two good keys
	createResp, err = client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	})
	if err != nil || len(createResp.KeyContent) != KMIPAESKeySizeBits/8 {
		t.Fatal(err)
	}
	createResp, err = client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "bbb",
		MountPoint:       "/b",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
	})
	if err != nil || len(createResp.KeyContent) != KMIPAESKeySizeBits/8 {
		t.Fatal(err)
	}
	// Retrieve both keys via automated retrieval without password
	autoRetrieveResp, err := client.AutoRetrieveKey(AutoRetrieveKeyReq{
		UUIDs:    []string{"aaa", "bbb", "does_not_exist"},
		Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(autoRetrieveResp.Granted) != 2 || len(autoRetrieveResp.Rejected) != 0 || !reflect.DeepEqual(autoRetrieveResp.Missing, []string{"does_not_exist"}) {
		t.Fatal(autoRetrieveResp.Granted, autoRetrieveResp.Rejected, autoRetrieveResp.Missing)
	}
	if len(autoRetrieveResp.Granted["aaa"].Key) != KMIPAESKeySizeBits/8 || len(autoRetrieveResp.Granted["bbb"].Key) != KMIPAESKeySizeBits/8 {
		t.Fatal(autoRetrieveResp.Granted)
	}
	verifyKeyA := func(recA keydb.Record) {
		if recA.UUID != "aaa" || recA.MountPoint != "/a" ||
			!reflect.DeepEqual(recA.MountOptions, []string{"ro", "noatime"}) || recA.AliveIntervalSec != 1 || recA.AliveCount != 4 ||
			recA.LastRetrieval.Timestamp == 0 || recA.LastRetrieval.Hostname != "localhost" || recA.LastRetrieval.IP != "127.0.0.1" ||
			len(recA.AliveMessages["127.0.0.1"]) != 1 {
			t.Fatal(recA)
		}
	}
	verifyKeyB := func(recB keydb.Record) {
		if recB.UUID != "bbb" || recB.MountPoint != "/b" ||
			!reflect.DeepEqual(recB.MountOptions, []string{"ro", "noatime"}) || recB.AliveIntervalSec != 1 || recB.AliveCount != 4 ||
			recB.LastRetrieval.Timestamp == 0 || recB.LastRetrieval.Hostname != "localhost" || recB.LastRetrieval.IP != "127.0.0.1" ||
			len(recB.AliveMessages) != 1 || len(recB.AliveMessages["127.0.0.1"]) != 1 {
			t.Fatal(recB)
		}
	}
	verifyKeyA(autoRetrieveResp.Granted["aaa"])
	verifyKeyB(autoRetrieveResp.Granted["bbb"])

	// Retrieve a key for a second time should be checked against MaxActive limit
	autoRetrieveResp, err = client.AutoRetrieveKey(AutoRetrieveKeyReq{
		UUIDs:    []string{"aaa", "bbb", "does_not_exist"},
		Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(autoRetrieveResp.Granted) != 1 || !reflect.DeepEqual(autoRetrieveResp.Rejected, []string{"aaa"}) || !reflect.DeepEqual(autoRetrieveResp.Missing, []string{"does_not_exist"}) {
		t.Fatal(autoRetrieveResp.Granted, autoRetrieveResp.Rejected, autoRetrieveResp.Missing)
	}
	verifyKeyB(autoRetrieveResp.Granted["bbb"])

	// Forcibly retrieve both keys and verify
	if _, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: HashPassword(salt, "wrong password"),
		UUIDs:    []string{"aaa"},
		Hostname: "localhost",
	}); err == nil {
		t.Fatal("did not error")
	}
	manResp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		UUIDs:    []string{"aaa", "bbb", "does_not_exist"},
		Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manResp.Granted) != 2 || !reflect.DeepEqual(manResp.Missing, []string{"does_not_exist"}) {
		t.Fatal(manResp.Granted, manResp.Missing)
	}
	verifyKeyA(manResp.Granted["aaa"])
	verifyKeyB(manResp.Granted["bbb"])

	// Keep updating alive messages
	for i := 0; i < 8; i++ {
		if rejected, err := client.ReportAlive(ReportAliveReq{
			Hostname: "localhost",
			UUIDs:    []string{"aaa", "bbb"},
		}); err != nil || len(rejected) > 0 {
			t.Fatal(err, rejected)
		}
		time.Sleep(1 * time.Second)
	}

	// Reload server
	if err := client.ReloadDB(); err != nil {
		t.Fatal(err)
	}

	// Delete key
	if err := client.EraseKey(EraseKeyReq{
		Password: HashPassword(salt, "wrong password"),
		Hostname: "localhost",
		UUID:     "aaa",
	}); err == nil {
		t.Fatal("did not error")
	}
	// Erasing a non-existent key should not result in an error
	if err := client.EraseKey(EraseKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		Hostname: "localhost",
		UUID:     "doesnotexist",
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.EraseKey(EraseKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		Hostname: "localhost",
		UUID:     "aaa",
	}); err != nil {
		t.Fatal(err)
	}
	// Erasing a non-existent key should not result in an error
	if err := client.EraseKey(EraseKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		Hostname: "localhost",
		UUID:     "aaa",
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("About to run teardown")
}

func BenchmarkSaveKey(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if _, err := client.CreateKey(CreateKeyReq{
			Password:         HashPassword(salt, TEST_RPC_PASS),
			Hostname:         "localhost",
			UUID:             "aaa",
			MountPoint:       "/a",
			MountOptions:     []string{"ro", "noatime"},
			MaxActive:        -1,
			AliveIntervalSec: 1,
			AliveCount:       4,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkAutoRetrieveKey(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if resp, err := client.AutoRetrieveKey(AutoRetrieveKeyReq{
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(resp.Granted) != 1 {
			b.Fatal(err, resp)
		}
	}
	b.StopTimer()
}

func BenchmarkManualRetrieveKey(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
			Password: HashPassword(salt, TEST_RPC_PASS),
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(resp.Granted) != 1 {
			b.Fatal(err, resp)
		}
	}
	b.StopTimer()
}

func BenchmarkReportAlive(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all benchmark operations in a single goroutine to know the real performance
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	// Retrieve the key so that this computer becomes eligible to send alive messages
	if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		UUIDs:    []string{"aaa"},
		Hostname: "localhost",
	}); err != nil || len(resp.Granted) != 1 {
		b.Fatal(err, resp)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if rejected, err := client.ReportAlive(ReportAliveReq{
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(rejected) > 0 {
			b.Fatal(err, rejected)
		}
	}
	b.StopTimer()
}
