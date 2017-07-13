// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"fmt"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/sys"
	"path"
	"reflect"
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
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "illegal chara") {
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
	client, _, tearDown := StartTestServer(t)
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
			recA.LastRetrieval.Timestamp == 0 || recA.LastRetrieval.Hostname == "" || recA.LastRetrieval.IP == "" ||
			len(recA.AliveMessages) != 1 {
			t.Fatal(recA)
		}
		for _, hostAliveMessages := range recA.AliveMessages {
			if len(hostAliveMessages) != 1 {
				t.Fatal(recA)
			}
		}
	}
	verifyKeyB := func(recB keydb.Record) {
		if recB.UUID != "bbb" || recB.MountPoint != "/b" ||
			!reflect.DeepEqual(recB.MountOptions, []string{"ro", "noatime"}) || recB.AliveIntervalSec != 1 || recB.AliveCount != 4 ||
			recB.LastRetrieval.Timestamp == 0 || recB.LastRetrieval.Hostname == "" || recB.LastRetrieval.IP == "" ||
			len(recB.AliveMessages) != 1 {
			t.Fatal(recB)
		}
		for _, hostAliveMessages := range recB.AliveMessages {
			if len(hostAliveMessages) != 1 {
				t.Fatal(recB)
			}
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

func TestPendingCommands(t *testing.T) {
	client, server, tearDown := StartTestServer(t)
	defer tearDown(t)
	// Create a key that will host pending commands
	salt, err := client.GetSalt()
	if err != nil {
		t.Fatal(err)
	}
	client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "a-a-a-a",
		MountPoint:       "/",
		MountOptions:     []string{},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       1,
	})
	// Initially, there are no pending commands to be polled.
	cmds, err := client.PollCommand(PollCommandReq{
		UUIDs: []string{"a-a-a-a", "this-does-not-exist"},
	})
	if err != nil || len(cmds.Commands) > 0 {
		t.Fatal(err, cmds.Commands)
	}
	// Save four pending commands - first command is still valid and unseen
	rec, _ := server.KeyDB.GetByUUID("a-a-a-a")
	cmd1 := keydb.PendingCommand{
		ValidFrom: time.Now(),
		Validity:  10 * time.Hour,
		IP:        "127.0.0.1",
		Content:   "1",
	}
	rec.AddPendingCommand("127.0.0.1", cmd1)
	// Second command is expired
	rec.AddPendingCommand("127.0.0.1", keydb.PendingCommand{
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Validity:  1 * time.Minute,
		IP:        "127.0.0.1",
		Content:   "2",
	})
	// Third command is valid but already seen
	rec.AddPendingCommand("127.0.0.1", keydb.PendingCommand{
		ValidFrom:    time.Now(),
		Validity:     10 * time.Hour,
		IP:           "127.0.0.1",
		Content:      "3",
		SeenByClient: true,
	})
	// Fouth command has nothing to do with this computer
	rec.AddPendingCommand("another-computer", keydb.PendingCommand{
		ValidFrom: time.Now(),
		Validity:  10 * time.Hour,
		IP:        "another-computer",
		Content:   "4",
	})
	if _, err := server.KeyDB.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	// Poll action should only receive the first command - valid yet unseen
	cmds, err = client.PollCommand(PollCommandReq{
		UUIDs: []string{"a-a-a-a", "this-does-not-exist"},
	})
	if err != nil || len(cmds.Commands) != 1 {
		t.Fatal(err, cmds.Commands)
	}
	if !reflect.DeepEqual(cmds.Commands["a-a-a-a"], []keydb.PendingCommand{cmd1}) {
		t.Fatalf("\n%+v\n%+v\n", []keydb.PendingCommand{cmd1}, cmds.Commands)
	}
	// Polled command is now marked as seen
	rec, _ = server.KeyDB.GetByUUID("a-a-a-a")
	if cmd1 := rec.PendingCommands["127.0.0.1"][0]; !cmd1.SeenByClient {
		t.Fatal(cmd1)
	}
	// There are no more commands to be polled
	cmds, err = client.PollCommand(PollCommandReq{
		UUIDs: []string{"a-a-a-a", "this-does-not-exist"},
	})
	if err != nil || len(cmds.Commands) > 0 {
		t.Fatal(err, cmds.Commands)
	}
	// Record a result for a still valid command
	if err := client.SaveCommandResult(SaveCommandResultReq{
		UUID:           "a-a-a-a",
		CommandContent: "1",
		Result:         "result 1",
	}); err != nil {
		t.Fatal(err)
	}
	rec, _ = server.KeyDB.GetByUUID("a-a-a-a")
	if cmd1 := rec.PendingCommands["127.0.0.1"][0]; !cmd1.SeenByClient || cmd1.ClientResult != "result 1" {
		t.Fatal(cmd1)
	}
	// Saving result for a non-existent command should not crash anything
	if err := client.SaveCommandResult(SaveCommandResultReq{
		UUID:           "a-a-a-a",
		CommandContent: "does-not-exist",
		Result:         "dummy-result",
	}); err != nil {
		t.Fatal(err)
	}
	// All expired commands should have been cleared when a command result was saved, only cmd1 and cmd3 are left.
	if len(rec.PendingCommands["127.0.0.1"]) != 2 {
		t.Fatal(rec.PendingCommands)
	}
}
