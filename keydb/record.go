// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keydb

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"
	"time"
)

// A client computer actively using an encryption key regularly sends alive messages to the server.
type AliveMessage struct {
	Hostname  string // client computer's host name as reported by itself
	IP        string // client computer's IP as seen by this server
	Timestamp int64  // alive message's timestamp as seen by this server
}

/*
A key record that knows all about the encrypted file system, its mount point, and unlocking keys.
When stored on disk, the record resides in a file encoded in gob.
The binary encoding method is intentionally chosen to deter users from manually editing the files on disk.
*/
type Record struct {
	UUID             string                    // partition UUID
	Key              []byte                    // encryption key in plain form
	MountPoint       string                    // mount point on client computer
	MountOptions     []string                  // file system's mount options
	MaxActive        int                       // maximum allowed active key users (computers), set to <=0 to allow unlimited.
	LastRetrieval    AliveMessage              // the most recent host who retrieved this key
	AliveIntervalSec int                       // interval in seconds at which all client computers holding this key must report their liveness
	AliveCount       int                       // a client computer is considered dead after missing so many alive messages
	AliveMessages    map[string][]AliveMessage // recent alive messages (latest is last), string map key is the host IP as seen by this server.
}

// Return mount options in a single string, as accepted by mount command.
func (rec *Record) GetMountOptionStr() string {
	return strings.Join(rec.MountOptions, ",")
}

// Determine whether a host is still alive according to recent alive messages.
func (rec *Record) IsHostAlive(hostIP string) (alive bool, finalMessage AliveMessage) {
	if beat, found := rec.AliveMessages[hostIP]; found {
		if len(beat) == 0 {
			// Should not happen
			return false, AliveMessage{}
		}
		finalMessage = beat[len(beat)-1]
		alive = finalMessage.Timestamp >= time.Now().Unix()-int64(rec.AliveIntervalSec*rec.AliveCount)
	}
	return
}

// Remove all dead hosts from alive message history, return each dead host's final alive .
func (rec *Record) RemoveDeadHosts() (deadFinalMessage map[string]AliveMessage) {
	deadFinalMessage = make(map[string]AliveMessage)
	deadIPs := make([]string, 0, 8)
	for hostIP := range rec.AliveMessages {
		if alive, finalMessage := rec.IsHostAlive(hostIP); !alive {
			deadFinalMessage[hostIP] = finalMessage
			deadIPs = append(deadIPs, hostIP)
		}
	}
	// Remove dead IPs
	for _, deadIP := range deadIPs {
		delete(rec.AliveMessages, deadIP)
	}
	return
}

/*
If number of maximum active users must be enforced, determine number of active key users from alive message history -
if the maximum number is not yet exceeded, update last retrieval information and alive message history for the host;
if maximum number is already met, the last retrieval information and alive message history are left untouched.

If number of maximum active users is not enforced, the last retrieval information and alive message history are
unconditionally updated.
*/
func (rec *Record) UpdateLastRetrieval(latestBeat AliveMessage, checkMaxActive bool) (updateOK bool,
	deadFinalMessage map[string]AliveMessage) {
	// Remove dead hosts before checking number of active key users
	deadFinalMessage = rec.RemoveDeadHosts()
	if checkMaxActive && rec.MaxActive > 0 && len(rec.AliveMessages) >= rec.MaxActive {
		updateOK = false
		return
	}
	rec.LastRetrieval = latestBeat
	rec.AliveMessages[latestBeat.IP] = make([]AliveMessage, 0, rec.AliveCount)
	rec.AliveMessages[latestBeat.IP] = append(rec.AliveMessages[latestBeat.IP], latestBeat)
	updateOK = true
	return
}

// Record the latest alive message in message history.
func (rec *Record) UpdateAliveMessage(latestBeat AliveMessage) bool {
	if beats, found := rec.AliveMessages[latestBeat.IP]; found {
		if len(beats) >= rec.AliveCount {
			// Remove the oldest message and push the latest one to the end
			rec.AliveMessages[latestBeat.IP] = append(beats[len(beats)-rec.AliveCount+1:], latestBeat)
		} else {
			// Simply append the latest one to the end
			rec.AliveMessages[latestBeat.IP] = append(beats, latestBeat)
		}
		return true
	}
	return false
}

// Return an error if a record attribute does not make sense.
func (rec *Record) Validate() error {
	if len(rec.UUID) < 3 {
		return fmt.Errorf("UUID \"%s\" looks too short", rec.UUID)
	}
	if len(rec.Key) < 3 {
		return fmt.Errorf("Key looks too short (%d bytes)", len(rec.Key))
	}
	if len(rec.MountPoint) < 2 {
		return fmt.Errorf("Mount point \"%s\" looks too short", rec.MountPoint)
	}
	if rec.AliveIntervalSec < 1 {
		return fmt.Errorf("AliveIntervalSec is %d but it should be a positive integer", rec.AliveIntervalSec)
	}
	if rec.AliveCount < 1 {
		return fmt.Errorf("AliveCount is %d but it should be a positive integer", rec.AliveCount)
	}
	return nil
}

// Initialise all nil attributes.
func (rec *Record) FillBlanks() {
	if rec.Key == nil {
		rec.Key = []byte{}
	}
	if rec.MountOptions == nil {
		rec.MountOptions = []string{}
	}
	if rec.AliveMessages == nil {
		rec.AliveMessages = make(map[string][]AliveMessage)
	}
}

// Serialise the record into binary content using gob encoding.
func (rec *Record) Serialise() []byte {
	rec.FillBlanks()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(rec); err != nil {
		// Shall not happen
		panic(fmt.Errorf("Serialise: failed to encode gob for record %s - %v", rec.UUID, err))
	}
	return buf.Bytes()
}

// Deserialise record from input binary content using gob encoding.
func (rec *Record) Deserialise(in []byte) error {
	rec.FillBlanks()
	if err := gob.NewDecoder(bytes.NewReader(in)).Decode(&rec); err != nil {
		return fmt.Errorf("Deserialise: failed to decode record - %v", err)
	}
	return nil
}

// Format all attributes (except the binary key) for pretty printing, using the specified separator.
func (rec *Record) FormatAttrs(separator string) string {
	return fmt.Sprintf(`Timestamp="%d"%sIP="%s"%sHostname="%s"%sFileSystemUUID="%s"%sMountPoint="%s"%sMountOptions="%s"`,
		rec.LastRetrieval.Timestamp, separator,
		rec.LastRetrieval.IP, separator,
		rec.LastRetrieval.Hostname, separator,
		rec.UUID, separator,
		strings.Replace(rec.MountPoint, `"`, `\"`, -1), separator,
		rec.GetMountOptionStr())
}

type RecordSlice []Record // a slice of key database records that can be sorted by latest usage.

func (r RecordSlice) Len() int {
	return len(r)
}

func (r RecordSlice) Less(i, j int) bool {
	// Largest (latest) timestamp is to first appear in sorted list
	return r[i].LastRetrieval.Timestamp != 0 && r[i].LastRetrieval.Timestamp > r[j].LastRetrieval.Timestamp
}

func (r RecordSlice) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}
