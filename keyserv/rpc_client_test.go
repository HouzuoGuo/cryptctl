// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/sys"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestRPCCalls(t *testing.T) {
	client, tearDown := StartTestServer(t)
	defer tearDown(t)
	if err := client.Ping(PingRequest{Password: "wrong pass"}); err == nil {
		t.Fatal("did not error")
	}
	if err := client.Ping(PingRequest{Password: TEST_RPC_PASS}); err != nil {
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
	if err := scClient.Ping(PingRequest{Password: TEST_RPC_PASS}); err != nil {
		t.Fatal(err)
	}
	// Save a bogus key will result in error
	err = client.SaveKey(SaveKeyReq{Password: TEST_RPC_PASS, Hostname: "localhost", Record: keydb.Record{}})
	if err == nil {
		t.Fatal(err)
	}
	// Save two keys
	keyRec1 := keydb.Record{
		UUID:             "aaa",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}
	keyRec2 := keydb.Record{
		UUID:             "bbb",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/b",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}
	if err := client.SaveKey(SaveKeyReq{Password: "wrong pass", Hostname: "localhost", Record: keyRec1}); err == nil {
		t.Fatal("did not error")
	}
	if err := client.SaveKey(SaveKeyReq{Password: TEST_RPC_PASS, Hostname: "localhost", Record: keyRec1}); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveKey(SaveKeyReq{Password: TEST_RPC_PASS, Hostname: "localhost", Record: keyRec2}); err != nil {
		t.Fatal(err)
	}
	// Retrieve both keys without password
	resp, err := client.AutoRetrieveKey(AutoRetrieveKeyReq{
		UUIDs:    []string{"aaa", "bbb", "does_not_exist"},
		Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Granted) != 2 || len(resp.Rejected) != 0 || !reflect.DeepEqual(resp.Missing, []string{"does_not_exist"}) {
		t.Fatal(resp.Granted, resp.Rejected, resp.Missing)
	}
	verifyKeyA := func(recA keydb.Record) {
		if recA.UUID != "aaa" || !reflect.DeepEqual(recA.Key, []byte{0, 1, 2, 3}) || recA.MountPoint != "/a" ||
			!reflect.DeepEqual(recA.MountOptions, []string{"ro", "noatime"}) || recA.AliveIntervalSec != 1 || recA.AliveCount != 4 ||
			recA.LastRetrieval.Timestamp == 0 || recA.LastRetrieval.Hostname != "localhost" || recA.LastRetrieval.IP != "127.0.0.1" ||
			len(recA.AliveMessages["127.0.0.1"]) != 1 {
			t.Fatal(recA)
		}
	}
	verifyKeyB := func(recB keydb.Record) {
		if recB.UUID != "bbb" || !reflect.DeepEqual(recB.Key, []byte{0, 1, 2, 3}) || recB.MountPoint != "/b" ||
			!reflect.DeepEqual(recB.MountOptions, []string{"ro", "noatime"}) || recB.AliveIntervalSec != 1 || recB.AliveCount != 4 ||
			recB.LastRetrieval.Timestamp == 0 || recB.LastRetrieval.Hostname != "localhost" || recB.LastRetrieval.IP != "127.0.0.1" ||
			len(recB.AliveMessages) != 1 || len(recB.AliveMessages["127.0.0.1"]) != 1 {
			t.Fatal(recB)
		}
	}
	// Verify retrieved keys
	verifyKeyA(resp.Granted["aaa"])
	verifyKeyB(resp.Granted["bbb"])

	// Retrieve a key for a second time should be checked against MaxActive allowrance
	resp, err = client.AutoRetrieveKey(AutoRetrieveKeyReq{
		UUIDs:    []string{"aaa", "bbb", "does_not_exist"},
		Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Granted) != 1 || !reflect.DeepEqual(resp.Rejected, []string{"aaa"}) || !reflect.DeepEqual(resp.Missing, []string{"does_not_exist"}) {
		t.Fatal(resp.Granted, resp.Rejected, resp.Missing)
	}
	// Verify retrieved key bbb
	verifyKeyB(resp.Granted["bbb"])

	// Forcibly retrieve both keys and verify
	if _, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: "wrong password",
		UUIDs:    []string{"aaa"},
		Hostname: "localhost",
	}); err == nil {
		t.Fatal("did not error")
	}
	manResp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: TEST_RPC_PASS,
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
		Password: "wrongpass",
		Hostname: "localhost",
		UUID:     "aaa",
	}); err == nil {
		t.Fatal("did not error")
	}
	if err := client.EraseKey(EraseKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		UUID:     "doesnotexist",
	}); err == nil {
		t.Fatal("did not error")
	}
	if err := client.EraseKey(EraseKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		UUID:     "aaa",
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.EraseKey(EraseKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		UUID:     "aaa",
	}); err == nil {
		t.Fatal("did not error")
	}
}

func BenchmarkSaveKey(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		rec := keydb.Record{
			UUID:             "aaa",
			Key:              []byte{0, 1, 2, 3},
			MountPoint:       "/a",
			MountOptions:     []string{"ro", "noatime"},
			MaxActive:        -1,
			AliveIntervalSec: 1,
			AliveCount:       4,
		}
		if err := client.SaveKey(SaveKeyReq{
			Password: TEST_RPC_PASS,
			Hostname: "localhost",
			Record:   rec,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkAutoRetrieveKey(b *testing.B) {
	client, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	rec := keydb.Record{
		UUID:             "aaa",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}
	if err := client.SaveKey(SaveKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		Record:   rec,
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
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	rec := keydb.Record{
		UUID:             "aaa",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}
	if err := client.SaveKey(SaveKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		Record:   rec,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
			Password: TEST_RPC_PASS,
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
	// Run all benchmark operations in a single goroutine to know the real performance
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	rec := keydb.Record{
		UUID:             "aaa",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}
	if err := client.SaveKey(SaveKeyReq{
		Password: TEST_RPC_PASS,
		Hostname: "localhost",
		Record:   rec,
	}); err != nil {
		b.Fatal(err)
	}
	// Retrieve the key so that this computer becomes eligible to send alive messages
	if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: TEST_RPC_PASS,
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
