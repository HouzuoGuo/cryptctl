// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keydb

import (
	"reflect"
	"testing"
	"time"
)

func TestRecordValidate(t *testing.T) {
	rec := Record{
		UUID:             "goodgoodgoodgood",
		Key:              []byte{0, 1, 2, 3, 4, 5, 6, 7},
		MountPoint:       "/tmp/abcde",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	rec = Record{
		UUID:             "<3",
		Key:              []byte{0, 1, 2, 3, 4, 5, 6, 7},
		MountPoint:       "/tmp/abcde",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if rec.Validate() == nil {
		t.Fatal("did not error")
	}
	rec = Record{
		UUID:             "goodgoodgoodgood",
		Key:              []byte{0, 1},
		MountPoint:       "/tmp/abcde",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if rec.Validate() == nil {
		t.Fatal("did not error")
	}
	rec = Record{
		UUID:             "goodgoodgoodgood",
		Key:              []byte{0, 1, 2, 3, 4, 5, 6, 7},
		MountPoint:       "/",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if rec.Validate() == nil {
		t.Fatal("did not error")
	}
	rec = Record{
		UUID:             "goodgoodgoodgood",
		Key:              []byte{0, 1, 2, 3, 4, 5, 6, 7},
		MountPoint:       "/tmp/abcde",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 0,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if rec.Validate() == nil {
		t.Fatal("did not error")
	}
	rec = Record{
		UUID:             "goodgoodgoodgood",
		Key:              []byte{0, 1, 2, 3, 4, 5, 6, 7},
		MountPoint:       "/tmp/abcde",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 10,
		AliveCount:       0,
		AliveMessages:    map[string][]AliveMessage{},
	}
	if rec.Validate() == nil {
		t.Fatal("did not error")
	}
}

func TestRecordAliveMessage1(t *testing.T) {
	rec := Record{
		UUID:             "testuuid",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/tmp/a",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        0,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}
	// This record can be retrieved by arbitrary computers without restriction
	alive1 := AliveMessage{
		Hostname:  "host1",
		IP:        "ip1",
		Timestamp: time.Now().Unix(),
	}
	alive2 := AliveMessage{
		Hostname:  "host2",
		IP:        "ip2",
		Timestamp: time.Now().Unix(),
	}
	for i := 0; i < 10; i++ {
		if ok, deadFinal := rec.UpdateLastRetrieval(alive1, true); !ok || len(deadFinal) != 0 {
			t.Fatal(ok)
		}
		if ok, deadFinal := rec.UpdateLastRetrieval(alive2, true); !ok || len(deadFinal) != 0 {
			t.Fatal(ok)
		}
	}

}

func TestRecordAliveMessage2(t *testing.T) {
	rec := Record{
		UUID:             "testuuid",
		Key:              []byte{0, 1, 2, 3},
		MountPoint:       "/tmp/a",
		MountOptions:     []string{"rw", "noatime"},
		MaxActive:        2,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages:    map[string][]AliveMessage{},
	}

	// Manipulate alive messages
	initialAlive1 := AliveMessage{
		Hostname:  "host1",
		IP:        "ip1",
		Timestamp: time.Now().Unix(),
	}
	initialAlive2 := AliveMessage{
		Hostname:  "host2",
		IP:        "ip2",
		Timestamp: time.Now().Unix(),
	}
	// Retrieve the record from host 1
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive1, true); !ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	if !reflect.DeepEqual(rec.LastRetrieval, initialAlive1) {
		t.Fatal(rec.LastRetrieval)
	}
	if !reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{
		"ip1": []AliveMessage{initialAlive1},
	}) {
		t.Fatal(rec.AliveMessages)
	}
	// Retrieve the record from host 2
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive2, true); !ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	if !reflect.DeepEqual(rec.LastRetrieval, initialAlive2) {
		t.Fatal(rec.LastRetrieval)
	}
	if !reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{
		"ip1": []AliveMessage{initialAlive1},
		"ip2": []AliveMessage{initialAlive2},
	}) {
		t.Fatal(rec.AliveMessages)
	}
	// Retrieving the records again shall result in failure
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive1, true); ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive2, true); ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	// And failed retrieval events do not update alive or last retrieval attributes
	if !reflect.DeepEqual(rec.LastRetrieval, initialAlive2) {
		t.Fatal(rec.LastRetrieval)
	}
	if !reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{
		"ip1": []AliveMessage{initialAlive1},
		"ip2": []AliveMessage{initialAlive2},
	}) {
		t.Fatal(rec.AliveMessages)
	}
	// But retrieving the records forcibly will go ahead and update attributes
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive1, false); !ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	if ok, deadFinal := rec.UpdateLastRetrieval(initialAlive2, false); !ok || len(deadFinal) != 0 {
		t.Fatal(ok, deadFinal)
	}
	if !reflect.DeepEqual(rec.LastRetrieval, initialAlive2) {
		t.Fatal(rec.LastRetrieval)
	}
	if !reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{
		"ip1": []AliveMessage{initialAlive1},
		"ip2": []AliveMessage{initialAlive2},
	}) {
		t.Fatal(rec.AliveMessages)
	}
	// Both host 1 and host 2 are now allowed to update their alive message, history keeps 5 of those records.
	aliveMsgs1 := make([]AliveMessage, 0, 5)
	aliveMsgs2 := make([]AliveMessage, 0, 5)
	// Keep updating alive messages for 2 seconds
	for i := 0; i < 2; i++ {
		time.Sleep(1 * time.Second)
		newAlive1 := AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: time.Now().Unix(),
		}
		aliveMsgs1 = append(aliveMsgs1, newAlive1)
		newAlive2 := AliveMessage{
			Hostname:  "host2",
			IP:        "ip2",
			Timestamp: time.Now().Unix(),
		}
		aliveMsgs2 = append(aliveMsgs2, newAlive2)
		if !rec.UpdateAliveMessage(newAlive1) {
			t.Fatal("update failed")
		}
		if !rec.UpdateAliveMessage(newAlive2) {
			t.Fatal("update failed")
		}
	}
	// The alive message history should now be nearly full
	aliveHistory1 := make([]AliveMessage, 0, 4)
	aliveHistory1 = append(aliveHistory1, initialAlive1)
	aliveHistory1 = append(aliveHistory1, aliveMsgs1[0:2]...)
	aliveHistory2 := make([]AliveMessage, 0, 4)
	aliveHistory2 = append(aliveHistory2, initialAlive2)
	aliveHistory2 = append(aliveHistory2, aliveMsgs2[0:2]...)
	if !reflect.DeepEqual(rec.AliveMessages["ip1"], aliveHistory1) {
		t.Fatal(rec.AliveMessages["ip1"], aliveHistory1)
	}
	if !reflect.DeepEqual(rec.AliveMessages["ip2"], aliveHistory2) {
		t.Fatal(rec.AliveMessages["ip2"], aliveHistory2)
	}
	aliveMsgs1 = make([]AliveMessage, 0, 8)
	aliveMsgs2 = make([]AliveMessage, 0, 8)
	// Keep updating alive messages, so that total history count is greater than 4.
	for i := 0; i < 8; i++ {
		time.Sleep(1 * time.Second)
		newAlive1 := AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: time.Now().Unix(),
		}
		aliveMsgs1 = append(aliveMsgs1, newAlive1)
		newAlive2 := AliveMessage{
			Hostname:  "host2",
			IP:        "ip2",
			Timestamp: time.Now().Unix(),
		}
		aliveMsgs2 = append(aliveMsgs2, newAlive2)
		if !rec.UpdateAliveMessage(newAlive1) {
			t.Fatal("update failed")
		}
		if !rec.UpdateAliveMessage(newAlive2) {
			t.Fatal("update failed")
		}
	}
	aliveHistory1 = aliveMsgs1[4:8]
	aliveHistory2 = aliveMsgs2[4:8]
	if !reflect.DeepEqual(rec.AliveMessages["ip1"], aliveHistory1) {
		t.Fatal(rec.AliveMessages["ip1"], aliveHistory1)
	}
	if !reflect.DeepEqual(rec.AliveMessages["ip2"], aliveHistory2) {
		t.Fatal(rec.AliveMessages["ip2"], aliveHistory2)
	}
	// While maximum active users is reached, no other host may join in to update alive message
	if rec.UpdateAliveMessage(AliveMessage{Hostname: "host3", IP: "ip3", Timestamp: time.Now().Unix()}) {
		t.Fatal("should not have updated")
	}
	// History shall remain unchanged
	if !reflect.DeepEqual(rec.AliveMessages["ip1"], aliveHistory1) {
		t.Fatal(rec.AliveMessages["ip1"], aliveHistory1)
	}
	if !reflect.DeepEqual(rec.AliveMessages["ip2"], aliveHistory2) {
		t.Fatal(rec.AliveMessages["ip2"], aliveHistory2)
	}
	// If a host goes silent and then comes back online, it should still be able to update alive message of its record
	time.Sleep(5 * time.Second)
	backAlive1 := AliveMessage{
		Hostname:  "host1",
		IP:        "ip1",
		Timestamp: time.Now().Unix(),
	}
	if !rec.UpdateAliveMessage(backAlive1) {
		t.Fatal("did not update")
	}
	// Updating alive message does not clear dead hosts or dead messages, only UpdateLastRetrieval does.
	aliveHistory1 = make([]AliveMessage, 0, 4)
	aliveHistory1 = append(aliveHistory1, aliveMsgs1[5:8]...)
	aliveHistory1 = append(aliveHistory1, backAlive1)
	if !reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{"ip1": aliveHistory1, "ip2": aliveHistory2}) {
		t.Fatal(rec.AliveMessages)
	}
	// The record allows max. 2 users, ip1 is still online, ip2 is offline, so ip3 should be able to retrieve it.
	alive3 := AliveMessage{
		Hostname:  "host3",
		IP:        "ip3",
		Timestamp: time.Now().Unix(),
	}
	if rec.UpdateAliveMessage(alive3) {
		t.Fatal("should not do update before retrieve")
	}
	if ok, deadFinal := rec.UpdateLastRetrieval(alive3, true); !ok || !reflect.DeepEqual(deadFinal, map[string]AliveMessage{"ip2": aliveHistory2[len(aliveHistory2)-1]}) {
		t.Fatal(ok, deadFinal)
	}
	if !reflect.DeepEqual(rec.LastRetrieval, alive3) ||
		!reflect.DeepEqual(rec.AliveMessages, map[string][]AliveMessage{
			"ip1": aliveHistory1,
			"ip3": []AliveMessage{alive3},
		}) {
		t.Fatal(rec.LastRetrieval, rec.AliveMessages)
	}
}

func TestRecord(t *testing.T) {
	rec := Record{
		UUID:         "testuuid",
		ID:           "testid",
		Key:          []byte{0, 1, 2, 3},
		MountPoint:   "/tmp/a",
		MountOptions: []string{"rw", "noatime"},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 123456,
		},
		MaxActive:        2,
		AliveIntervalSec: 1,
		AliveCount:       4,
		AliveMessages: map[string][]AliveMessage{"ip1": []AliveMessage{
			{
				Hostname:  "host1",
				IP:        "ip1",
				Timestamp: 123456,
			},
			{
				Hostname:  "host1",
				IP:        "ip1",
				Timestamp: 123456,
			},
		}},
	}

	// Join mount opts
	if str := rec.GetMountOptionStr(); str != "rw,noatime" {
		t.Fatal(str)
	}

	// Serialise all record attributes and then deserialise
	serialised := rec.Serialise()
	var deserialised Record
	if err := deserialised.Deserialise(serialised); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(deserialised, rec) {
		t.Fatal(deserialised)
	}

	// Format as string
	if s := rec.FormatAttrs("|"); s != `Timestamp="123456"|IP="ip1"|Hostname="host1"|FileSystemUUID="testuuid"|KMIPID="testid"|MountPoint="/tmp/a"|MountOptions="rw,noatime"` {
		t.Fatal(s)
	}
}

func TestRecord_RemoveExpiredPendingCommands(t *testing.T) {
	rec := Record{
		UUID:         "testuuid",
		ID:           "testid",
		Key:          []byte{0, 1, 2, 3},
		MountPoint:   "/tmp/a",
		MountOptions: []string{"rw", "noatime"},
		LastRetrieval: AliveMessage{
			Hostname:  "host1",
			IP:        "ip1",
			Timestamp: 123456,
		},
		MaxActive:        2,
		AliveIntervalSec: 1,
		AliveCount:       4,
		PendingCommands:  make(map[string][]PendingCommand),
	}
	rec.AddPendingCommand("1.1.1.1", PendingCommand{
		// Expired right away
		ValidFrom: time.Now().Add(-1 * time.Second),
		Validity:  1 * time.Second,
	})
	rec.AddPendingCommand("1.1.1.1", PendingCommand{
		// Expiring in a minute
		ValidFrom: time.Now(),
		Validity:  1 * time.Minute,
	})
	rec.AddPendingCommand("1.1.1.1", PendingCommand{
		// Not expiring anytime soon
		ValidFrom: time.Now(),
		Validity:  1 * time.Hour,
	})
	rec.AddPendingCommand("2.2.2.2", PendingCommand{
		// Expired right away
		ValidFrom: time.Now().Add(-1 * time.Second),
		Validity:  1 * time.Second,
	})
	rec.RemoveExpiredPendingCommands()
	// 1.1.1.1 has one command remaining
	// 2.2.2.2 is removed because there are no more commands in history
	if len(rec.PendingCommands) != 1 || len(rec.PendingCommands["1.1.1.1"]) != 2 {
		t.Fatalf("%+v", rec.PendingCommands)
	}
}
