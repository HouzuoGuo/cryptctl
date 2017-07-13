// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keydb

import (
	"os"
	"reflect"
	"testing"
	"time"
)

const TestDBDir = "/tmp/cryptctl-dbtest"

func TestRecordCRUD(t *testing.T) {
	defer os.RemoveAll(TestDBDir)
	os.RemoveAll(TestDBDir)
	db, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	// Insert two records
	aliveMsg := AliveMessage{
		Hostname:  "host1",
		IP:        "ip1",
		Timestamp: time.Now().Unix(),
	}
	rec1 := Record{
		UUID:             "1",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/tmp/2",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
		PendingCommands:  make(map[string][]PendingCommand),
	}
	rec1Alive := rec1
	rec1Alive.LastRetrieval = aliveMsg
	rec1Alive.AliveMessages = map[string][]AliveMessage{aliveMsg.IP: []AliveMessage{aliveMsg}}
	rec2 := Record{
		UUID:             "2",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/tmp/2",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        1,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
		PendingCommands:  make(map[string][]PendingCommand),
	}
	rec2Alive := rec2
	rec2Alive.LastRetrieval = aliveMsg
	rec2Alive.AliveMessages = map[string][]AliveMessage{aliveMsg.IP: []AliveMessage{aliveMsg}}
	if seq, err := db.Upsert(rec1); err != nil || seq != "1" {
		t.Fatal(err, seq)
	}
	if seq, err := db.Upsert(rec2); err != nil || seq != "2" {
		t.Fatal(err, seq)
	}
	// Match sequence number in my copy of records with their should-be ones
	rec1.ID = "1"
	rec1Alive.ID = "1"
	rec2.ID = "2"
	rec2Alive.ID = "2"
	// Select one record and then select both records
	if found, rejected, missing := db.Select(aliveMsg, true, "1", "doesnotexist"); !reflect.DeepEqual(found, map[string]Record{rec1.UUID: rec1Alive}) ||
		!reflect.DeepEqual(rejected, []string{}) ||
		!reflect.DeepEqual(missing, []string{"doesnotexist"}) {
		t.Fatalf("\n%+v\n%+v\n%+v\n%+v\n", found, map[string]Record{rec1.UUID: rec1Alive}, rejected, missing)
	}
	if found, rejected, missing := db.Select(aliveMsg, true, "1", "doesnotexist", "2"); !reflect.DeepEqual(found, map[string]Record{rec2.UUID: rec2Alive}) ||
		!reflect.DeepEqual(rejected, []string{"1"}) ||
		!reflect.DeepEqual(missing, []string{"doesnotexist"}) {
		t.Fatal(found, rejected, missing)
	}
	if found, rejected, missing := db.Select(aliveMsg, false, "1", "doesnotexist", "2"); !reflect.DeepEqual(found, map[string]Record{rec1.UUID: rec1Alive, rec2.UUID: rec2Alive}) ||
		!reflect.DeepEqual(rejected, []string{}) ||
		!reflect.DeepEqual(missing, []string{"doesnotexist"}) {
		t.Fatal(found, rejected, missing)
	}
	// Update alive message on both records
	newAlive := AliveMessage{
		Hostname:  "host1",
		IP:        "ip1",
		Timestamp: time.Now().Unix(),
	}
	if rejected := db.UpdateAliveMessage(newAlive, "1", "2", "doesnotexist"); !reflect.DeepEqual(rejected, []string{"doesnotexist"}) {
		t.Fatal(rejected)
	}
	if len(db.RecordsByUUID["1"].AliveMessages["ip1"]) != 2 || len(db.RecordsByUUID["2"].AliveMessages["ip1"]) != 2 {
		t.Fatal(db.RecordsByUUID)
	}
	if len(db.RecordsByID["1"].AliveMessages["ip1"]) != 2 || len(db.RecordsByID["2"].AliveMessages["ip1"]) != 2 {
		t.Fatal(db.RecordsByUUID)
	}
	// Erase a record
	if err := db.Erase("doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
	if err := db.Erase(rec1.UUID); err != nil {
		t.Fatal(err)
	}
	if found, rejected, missing := db.Select(aliveMsg, true, "1"); len(found) != 0 ||
		!reflect.DeepEqual(rejected, []string{}) ||
		!reflect.DeepEqual(missing, []string{"1"}) {
		t.Fatal(found, rejected, missing)
	}
	// Reload database and test query once more (2 is already retrieved and hence it shall be rejected)
	db, err = OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	if found, rejected, missing := db.Select(aliveMsg, true, "1", "2"); len(found) != 0 ||
		!reflect.DeepEqual(rejected, []string{"2"}) ||
		!reflect.DeepEqual(missing, []string{"1"}) {
		t.Fatal(found, missing)
	}
}

func TestOpenDBOneRecord(t *testing.T) {
	defer os.RemoveAll(TestDBDir)
	os.RemoveAll(TestDBDir)
	db, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	rec := Record{
		UUID:         "a",
		Key:          []byte{1, 2, 3},
		MountPoint:   "/a",
		MountOptions: []string{},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 3,
		},
		AliveMessages:   make(map[string][]AliveMessage),
		PendingCommands: make(map[string][]PendingCommand),
	}
	if seq, err := db.Upsert(rec); err != nil || seq != "1" {
		t.Fatal(err)
	}
	dbOneRecord, err := OpenDBOneRecord(TestDBDir, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(dbOneRecord.RecordsByUUID) != 1 {
		t.Fatal(dbOneRecord.RecordsByUUID)
	}
	rec.ID = "1"
	if recA, found := dbOneRecord.GetByUUID("a"); !found || !reflect.DeepEqual(recA, rec) {
		t.Fatal(recA, found)
	}
	if recA, found := dbOneRecord.GetByID("1"); !found || !reflect.DeepEqual(recA, rec) {
		t.Fatal(recA, found)
	}
	if _, found := dbOneRecord.GetByUUID("doesnotexist"); found {
		t.Fatal("false positive")
	}
	if _, found := dbOneRecord.GetByID("78598123"); found {
		t.Fatal("false positive")
	}
}

func TestList(t *testing.T) {
	defer os.RemoveAll(TestDBDir)
	db, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	// Insert three records and get them back in sorted order
	rec1 := Record{
		UUID:         "a",
		Key:          []byte{1, 2, 3},
		MountPoint:   "/a",
		MountOptions: []string{},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 3,
		},
		AliveMessages:   make(map[string][]AliveMessage),
		PendingCommands: make(map[string][]PendingCommand),
	}
	rec1NoKey := rec1
	rec1NoKey.Key = nil
	rec2 := Record{
		UUID:         "b",
		Key:          []byte{1, 2, 3},
		MountPoint:   "/b",
		MountOptions: []string{},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 1,
		},
		AliveMessages:   make(map[string][]AliveMessage),
		PendingCommands: make(map[string][]PendingCommand),
	}
	rec2NoKey := rec2
	rec2NoKey.Key = nil
	rec3 := Record{
		UUID:         "c",
		Key:          []byte{1, 2, 3},
		MountPoint:   "/c",
		MountOptions: []string{},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 2,
		},
		AliveMessages:   make(map[string][]AliveMessage),
		PendingCommands: make(map[string][]PendingCommand),
	}
	rec3NoKey := rec3
	rec3NoKey.Key = nil
	if seq, err := db.Upsert(rec1); err != nil || seq != "1" {
		t.Fatal(err, seq)
	}
	if seq, err := db.Upsert(rec2); err != nil || seq != "2" {
		t.Fatal(err)
	}
	if seq, err := db.Upsert(rec3); err != nil || seq != "3" {
		t.Fatal(err)
	}
	rec1NoKey.ID = "1"
	rec2NoKey.ID = "2"
	rec3NoKey.ID = "3"
	recs := db.List()
	if !reflect.DeepEqual(recs[0], rec1NoKey) ||
		!reflect.DeepEqual(recs[1], rec3NoKey) ||
		!reflect.DeepEqual(recs[2], rec2NoKey) {
		t.Fatal(recs)
	}
}

func TestDB_LoadRecord(t *testing.T) {
	defer os.RemoveAll(TestDBDir)
	os.RemoveAll(TestDBDir)
	// Open identical directory in two database instances
	db, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	// Create a record in the first database instance
	rec := Record{
		UUID:         "a",
		Key:          []byte{1, 2, 3},
		MountPoint:   "/a",
		MountOptions: []string{},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 3,
		},
		AliveMessages: make(map[string][]AliveMessage),
	}
	if seq, err := db.Upsert(rec); err != nil || seq != "1" {
		t.Fatal(err)
	}
	// Load the newly created record in the second database instance
	if err := db2.ReloadRecord("a"); err != nil {
		t.Fatal(err)
	}
	if rec, found := db2.GetByID("1"); !found || rec.UUID != "a" {
		t.Fatal(rec, found)
	}
	if err := db2.ReloadRecord("doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
}

func TestDB_UpdateSeenFlag(t *testing.T) {
	defer os.RemoveAll(TestDBDir)
	os.RemoveAll(TestDBDir)
	db, err := OpenDB(TestDBDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Upsert(Record{ID: "id1", UUID: "a", Key: []byte{}}); err != nil {
		t.Fatal(err)
	}

	start := time.Now()

	recA := db.RecordsByUUID["a"]
	// Record 1 is valid
	recA.AddPendingCommand("1.1.1.1", PendingCommand{
		ValidFrom: start,
		Validity:  10 * time.Hour,
		IP:        "1.1.1.1",
		Content:   "1st command",
	})
	// Record 2 is expired
	recA.AddPendingCommand("1.1.1.1", PendingCommand{
		ValidFrom: start.Add(-11 * time.Hour),
		Validity:  10 * time.Hour,
		IP:        "1.1.1.1",
		Content:   "2nd command",
	})
	// Record 3 is valid
	recA.AddPendingCommand("2.2.2.2", PendingCommand{
		ValidFrom: start,
		Validity:  10 * time.Hour,
		IP:        "2.2.2.2",
		Content:   "3rd command",
	})
	db.RecordsByUUID["a"] = recA

	db.UpdateSeenFlag("a", "1.1.1.1", "1st command")
	db.UpdateCommandResult("a", "1.1.1.1", "2nd command", "success")
	db.UpdateCommandResult("a", "2.2.2.2", "3rd command", "failure")

	expected := map[string][]PendingCommand{
		"1.1.1.1": {
			{
				ValidFrom:    start,
				Validity:     10 * time.Hour,
				IP:           "1.1.1.1",
				Content:      "1st command",
				SeenByClient: true,
			},
		},
		"2.2.2.2": {
			{
				ValidFrom:    start,
				Validity:     10 * time.Hour,
				IP:           "2.2.2.2",
				Content:      "3rd command",
				SeenByClient: true,
				ClientResult: "failure",
			},
		},
	}
	if !reflect.DeepEqual(expected, db.RecordsByUUID["a"].PendingCommands) {
		t.Fatalf("\n%+v\n%+v\n", expected, db.RecordsByUUID["a"].PendingCommands)
	}
	if !reflect.DeepEqual(expected, db.RecordsByID["id1"].PendingCommands) {
		t.Fatalf("\n%+v\n%+v\n", expected, db.RecordsByID["id1"].PendingCommands)
	}
}
