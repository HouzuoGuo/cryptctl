// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
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
	"sort"
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
	Dir     string
	Records map[string]Record // string is record UUID
	Lock    *sync.RWMutex     // prevent concurrent access to records
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
	if err := os.MkdirAll(dir, DB_DIR_FILE_MODE); err != nil {
		return nil, fmt.Errorf("OpenDB: failed to make db directory \"%s\" - %v", dir, err)
	}
	db = &DB{Dir: dir, Lock: new(sync.RWMutex), Records: map[string]Record{}}
	keyRecord, err := db.LoadRecord(path.Join(dir, recordUUID))
	if err == nil {
		db.Records[recordUUID] = keyRecord
	}
	return
}

// Read and deserialise a key record from file system.
func (db *DB) LoadRecord(absPath string) (keyRecord Record, err error) {
	keyRecordContent, err := ioutil.ReadFile(absPath)
	if err != nil {
		return
	}
	err = keyRecord.Deserialise(keyRecordContent)
	return
}

// (Re)load database records.
func (db *DB) ReloadDB() error {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	db.Records = make(map[string]Record)
	keyFiles, err := ioutil.ReadDir(db.Dir)
	if err != nil {
		return fmt.Errorf("ReloadDB: failed to read directory \"%s\" - %v", db.Dir, err)
	}
	for _, fileInfo := range keyFiles {
		// Read and deserialise each record file
		filePath := path.Join(db.Dir, fileInfo.Name())
		if keyRecord, err := db.LoadRecord(filePath); err == nil {
			db.Records[keyRecord.UUID] = keyRecord
		} else {
			log.Printf("ReloadDB: non-fatal failure occured when reading record \"%s\" - %v", filePath, err)
		}
	}
	log.Printf("ReloadDB: successfully loaded database of %d records", len(db.Records))
	return nil
}

// Log the input error, then return a new error with a more comprehensive and friendlier message.
func (db *DB) logIOFailure(rec Record, err error) error {
	failMessage := fmt.Sprintf("keydb: failed to write db record file for %s - %v", rec.UUID, err)
	log.Print(failMessage)
	return errors.New(failMessage)
}

// Create/update and immediately persist a key record. IO errors are returned and logged to stderr.
func (db *DB) upsert(rec Record, doSync bool) error {
	fh, err := os.OpenFile(path.Join(db.Dir, rec.UUID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DB_REC_FILE_MODE)
	if err == nil {
		defer fh.Close()
	} else {
		return db.logIOFailure(rec, err)
	}
	if _, err := fh.Write(rec.Serialise()); err != nil {
		return db.logIOFailure(rec, err)
	}
	if doSync {
		if err := fh.Sync(); err != nil {
			return db.logIOFailure(rec, err)
		}
	}
	db.Records[rec.UUID] = rec
	return nil
}

// Create/update and immediately persist a key record. IO errors are returned and logged to stderr.
func (db *DB) Upsert(rec Record) error {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	return db.upsert(rec, true)
}

// Record and immediately persist alive message that came from a host.
func (db *DB) UpdateAliveMessage(latest AliveMessage, uuids ...string) (rejected []string) {
	rejected = make([]string, 0, 8)
	db.Lock.Lock()
	defer db.Lock.Unlock()
	for _, uuid := range uuids {
		if record, exists := db.Records[uuid]; exists {
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
		if record, exists := db.Records[uuid]; exists {
			// Log dead hosts
			ok, deadFinalMessage := record.UpdateLastRetrieval(aliveMessage, checkMaxActive)
			if len(deadFinalMessage) > 0 {
				log.Printf("Select: record %s has not heard %d from these hosts: %+v", uuid, time.Now().Unix(), deadFinalMessage)
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
	sortedRecords = make([]Record, 0, len(db.Records))
	for _, rec := range db.Records {
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
	if _, exists := db.Records[uuid]; !exists {
		return fmt.Errorf("Delete: record '%s' does not exist", uuid)
	}
	delete(db.Records, uuid)
	if err := fs.SecureErase(path.Join(db.Dir, uuid), true); err != nil {
		return fmt.Errorf("Delete: failed to delete db record for %s - %v", uuid, err)
	}
	return nil
}
