// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keydb

import (
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	DB_DIR_FILE_MODE = 0700
	DB_REC_FILE_MODE = 0600
)

/*
The database of key records reside in a directory, each key record is serialised into a file.
All key records are read into memory upon startup for fast retrieval.
All exported functions are safe for concurrent usage.
*/
type DB struct {
	Dir             string
	RecordsByUUID   map[string]Record // key is record UUID string
	RecordsByID     map[string]Record // when saved by built-in KMIP server, the ID is a sequence number; otherwise it can be anything.
	LastSequenceNum int64             // the last sequence number currently in-use
	Lock            *sync.RWMutex     // prevent concurrent access to records
}

// Open a key database directory and read all key records into memory. Caller should consider to lock memory.
func OpenDB(dir string) (db *DB, err error) {
	if err := os.MkdirAll(dir, DB_DIR_FILE_MODE); err != nil {
		return nil, fmt.Errorf("OpenDB: failed to make db directory \"%s\" - %v", dir, err)
	}
	db = &DB{Dir: dir, Lock: new(sync.RWMutex)}
	err = db.ReloadDB()
	return
}

/*
Open a key database directory but only load a single record into memory.
If the specified record is not found in file system, an error is returned
Caller should consider ot lock memory.
*/
func OpenDBOneRecord(dir, recordUUID string) (db *DB, err error) {
	if err = ValidateUUID(recordUUID); err != nil {
		return
	}
	if err := os.MkdirAll(dir, DB_DIR_FILE_MODE); err != nil {
		return nil, fmt.Errorf("OpenDBOneRecord: failed to make db directory \"%s\" - %v", dir, err)
	}
	db = &DB{Dir: dir, Lock: new(sync.RWMutex), RecordsByUUID: map[string]Record{}, RecordsByID: map[string]Record{}}
	keyRecord, err := db.ReadRecord(path.Join(dir, recordUUID))
	if err == nil {
		db.RecordsByUUID[recordUUID] = keyRecord
		db.RecordsByID[keyRecord.ID] = keyRecord
	}
	return
}

// Read and deserialise a key record from file system.
func (db *DB) ReadRecord(absPath string) (keyRecord Record, err error) {
	keyRecordContent, err := ioutil.ReadFile(absPath)
	if err != nil {
		return
	}
	err = keyRecord.Deserialise(keyRecordContent)
	return
}

/*
ReloadRecord reads the latest record content corresponding to the UUID from disk file and loads it into memory.
The function panics if the record version is not the latest.
*/
func (db *DB) ReloadRecord(uuid string) error {
	if err := ValidateUUID(uuid); err != nil {
		return err
	}
	rec, err := db.ReadRecord(path.Join(db.Dir, uuid))
	if err != nil {
		return err
	}
	db.RecordsByUUID[uuid] = rec
	db.RecordsByID[rec.ID] = rec
	return nil
}

// (Re)load database records.
func (db *DB) ReloadDB() error {
	db.Lock.Lock()
	defer db.Lock.Unlock()

	db.RecordsByUUID = make(map[string]Record)
	db.RecordsByID = make(map[string]Record)
	keyFiles, err := ioutil.ReadDir(db.Dir)
	if err != nil {
		return fmt.Errorf("DB.ReloadDB: failed to read directory \"%s\" - %v", db.Dir, err)
	}

	var lastSequenceNum int64
	recordsToUpgrade := make([]Record, 0, 0)
	// Read and deserialise each record file while finding out the last sequence number
	for _, fileInfo := range keyFiles {
		filePath := path.Join(db.Dir, fileInfo.Name())
		if keyRecord, err := db.ReadRecord(filePath); err == nil {
			if keyRecord.Version == CurrentRecordVersion {
				db.RecordsByUUID[keyRecord.UUID] = keyRecord
				db.RecordsByID[keyRecord.ID] = keyRecord
				/*
					If the record was created by built-in KMIP server, the key is a sequence number.
					Otherwise, it can be anything such as a number or ID or string.
				*/
				idSeq, _ := strconv.ParseInt(keyRecord.ID, 10, 64)
				if idSeq > lastSequenceNum {
					lastSequenceNum = idSeq
				}
			} else {
				// Upgrade the record and place them into maps later
				recordsToUpgrade = append(recordsToUpgrade, keyRecord)
			}
		} else {
			log.Printf("DB.ReloadDB: non-fatal failure occured when reading record \"%s\" - %v", filePath, err)
		}
	}
	/*
		The record upgrade process must takes place after all records are successfully read, because
		 the upgrade from version 0 to 1 involves assigning records a sequence number that can only be determined
		 after having read all records.
	*/
	for _, record := range recordsToUpgrade {
		if err := db.UpgradeRecord(record); err != nil {
			return err
		}
	}
	log.Printf("DB.ReloadDB: successfully loaded database of %d records", len(db.RecordsByUUID))
	return nil
}

// Upgrade a record to the latest version.
func (db *DB) UpgradeRecord(record Record) error {
	switch record.Version {
	case 0:
		return db.UpgradeRecordToVersion1(record)
	case 1:
		// Version 2 brings PendingCommands map
		record.Version = 2
		record.PendingCommands = make(map[string][]PendingCommand)
		if _, err := db.upsert(record, true); err != nil {
			return err
		}
	default:
		return nil
	}
	return nil
}

/*
Record version 0 was the first version prior and equal to cryptctl 1.99 pre-release.
Version number 1 gives each record a KMIP key ID, a creation time, and knows whether key content is located on external KMIP server.
*/
func (db *DB) UpgradeRecordToVersion1(record Record) error {
	/*
		By contract, upsert assigns a record a sequence number if it does not yet have one.
		After successful update, the record is updated in both RecordsByUUID and RecordsByID.
	*/
	_, err := db.upsert(record, true)
	if err != nil {
		return err
	}
	log.Printf("DB.UpgradeRecordToVersion1: just upgraded record \"%s\"", record.UUID)
	return nil
}

// Log the input error, then return a new error with a more comprehensive and friendlier message.
func (db *DB) logIOFailure(rec Record, err error) error {
	failMessage := fmt.Sprintf("keydb: failed to write db record file for %s - %v", rec.UUID, err)
	log.Print(failMessage)
	return errors.New(failMessage)
}

/*
Create/update and immediately persist a key record.
If the record does not yet have a KMIP ID, it will be given a sequence number as ID.
IO errors are returned and logged to stderr.
*/
func (db *DB) upsert(rec Record, doSync bool) (string, error) {
	// Initialise incomplete nil values of the struct
	if rec.PendingCommands == nil {
		rec.PendingCommands = make(map[string][]PendingCommand)
	}
	if rec.AliveMessages == nil {
		rec.AliveMessages = make(map[string][]AliveMessage)
	}
	// For a new record that doesn't yet have a sequence number, assign it the next number in sequence.
	if rec.ID == "" {
		db.LastSequenceNum++
		rec.ID = strconv.FormatInt(db.LastSequenceNum, 10)
	}
	fh, err := os.OpenFile(path.Join(db.Dir, rec.UUID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DB_REC_FILE_MODE)
	if err == nil {
		defer fh.Close()
	} else {
		return "", db.logIOFailure(rec, err)
	}
	if _, err := fh.Write(rec.Serialise()); err != nil {
		return "", db.logIOFailure(rec, err)
	}
	if doSync {
		if err := fh.Sync(); err != nil {
			return "", db.logIOFailure(rec, err)
		}
	}
	// The in-memory copy of record is kept up to date with the copy on disk.
	db.RecordsByUUID[rec.UUID] = rec
	db.RecordsByID[rec.ID] = rec
	return rec.ID, err
}

// Create/update and immediately persist a key record. IO errors are returned and logged to stderr.
func (db *DB) Upsert(rec Record) (kmipID string, err error) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	return db.upsert(rec, true)
}

// Retrieve a key record by its KMIP ID.
func (db *DB) GetByID(id string) (rec Record, found bool) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	rec, found = db.RecordsByID[id]
	return
}

// Retrieve a key record by its disk UUID.
func (db *DB) GetByUUID(uuid string) (rec Record, found bool) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	rec, found = db.RecordsByUUID[uuid]
	return
}

// Record and immediately persist alive message that came from a host.
func (db *DB) UpdateAliveMessage(latest AliveMessage, uuids ...string) (rejected []string) {
	rejected = make([]string, 0, 8)
	db.Lock.Lock()
	defer db.Lock.Unlock()
	for _, uuid := range uuids {
		if record, exists := db.RecordsByUUID[uuid]; exists {
			if record.UpdateAliveMessage(latest) {
				db.upsert(record, false) // IO error is logged
			} else {
				// Host is no longer considered to be alive
				rejected = append(rejected, uuid)
			}
		} else {
			// UUID record disappeared
			rejected = append(rejected, uuid)
		}
	}
	return
}

// Retrieve key records that belong to those UUIDs, and immediately persist last-retrieval information on those records.
func (db *DB) Select(aliveMessage AliveMessage, checkMaxActive bool, uuids ...string) (found map[string]Record, rejected, missing []string) {
	found = make(map[string]Record)
	rejected = make([]string, 0, 8)
	missing = make([]string, 0, 8)
	db.Lock.Lock()
	defer db.Lock.Unlock()
	for _, uuid := range uuids {
		if record, exists := db.RecordsByUUID[uuid]; exists {
			// Log dead hosts
			ok, deadFinalMessage := record.UpdateLastRetrieval(aliveMessage, checkMaxActive)
			if len(deadFinalMessage) > 0 {
				log.Printf("DB.Select: record %s has not heard %d from these hosts: %+v", uuid, time.Now().Unix(), deadFinalMessage)
			}
			if ok {
				db.upsert(record, true) // IO error is logged
				found[record.UUID] = record
			} else {
				// Too many active hosts
				rejected = append(rejected, uuid)
			}
		} else {
			missing = append(missing, uuid)
		}
	}
	return
}

// Return all key records (not including key content) sorted according to latest usage.
func (db *DB) List() (sortedRecords RecordSlice) {
	db.Lock.RLock()
	defer db.Lock.RUnlock()
	sortedRecords = make([]Record, 0, len(db.RecordsByUUID))
	for _, rec := range db.RecordsByUUID {
		// Do not return encryption key
		rec.Key = nil
		sortedRecords = append(sortedRecords, rec)
	}
	sort.Sort(sortedRecords)
	return
}

// Erase a record from both memory and disk.
func (db *DB) Erase(uuid string) error {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	rec, exists := db.RecordsByUUID[uuid]
	if !exists {
		return fmt.Errorf("DB.Erase: record '%s' does not exist", uuid)
	}
	delete(db.RecordsByUUID, uuid)
	delete(db.RecordsByID, rec.ID)
	if err := fs.SecureErase(path.Join(db.Dir, uuid), true); err != nil {
		return fmt.Errorf("DB.Erase: failed to delete db record for %s - %v", uuid, err)
	}
	return nil
}

/*
UpdateSeenFlag updates "seen" flag of a pending command to true.
The flag is updated by looking for a command record matched to the specified IP, array index, and content.
If a matching record is not found, the function will do nothing.
*/
func (db *DB) UpdateSeenFlag(uuid, ip string, content interface{}) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	rec, found := db.RecordsByUUID[uuid]
	if !found {
		return
	}
	cmds, found := rec.PendingCommands[ip]
	for i, cmd := range cmds {
		if reflect.DeepEqual(cmd.Content, content) {
			cmds[i].SeenByClient = true
			break
		}
	}
	db.upsert(rec, false)
}

/*
UpdateCommandResult updates execution result of a pending command.
The pending command is updated by looking for a command record matched to the specified UUID, IP, and content.
If a matching record is not found, the function will do nothing.
*/
func (db *DB) UpdateCommandResult(uuid, ip string, content interface{}, result string) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	rec, found := db.RecordsByUUID[uuid]
	if !found {
		return
	}
	cmds, found := rec.PendingCommands[ip]
	for i, cmd := range cmds {
		if cmd.Content == content {
			cmds[i].SeenByClient = true
			cmds[i].ClientResult = result
			break
		}
	}
	db.upsert(rec, false)
}
