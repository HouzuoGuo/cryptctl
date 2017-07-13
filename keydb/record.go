// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keydb

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	CurrentRecordVersion = 2 // CurrentRecordVersion is the version of new database records to be created by cryptctl.
)

var RegexUUID = regexp.MustCompile("^[a-zA-Z0-9-]+$") // RegexUUID matches characters that are allowed in a UUID

/*
ValidateUUID returns an error only if the input string is empty, or if there are illegal
characters among the input.
*/
func ValidateUUID(in string) error {
	if in == "" {
		return errors.New("ValidateUUID: UUID must not be empty")
	} else if !RegexUUID.MatchString(in) {
		return errors.New("ValidateUUID: illegal characters appeared in UUID")
	}
	return nil
}

/*
AliveMessage is a component of key database record, it represents a heartbeat sent by a computer who is actively
using an encryption key - i.e. the encrypted disk is currently unlocked and online.
*/
type AliveMessage struct {
	Hostname  string // Hostname is the host name reported by client computer itself.
	IP        string // IP is the client computer's IP as seen by cryptctl server.
	Timestamp int64  // Timestamp is the moment the message arrived at cryptctl server.
}

// PendingCommand is a time-restricted command issued by cryptctl server administrator to be polled by a client.
type PendingCommand struct {
	ValidFrom    time.Time     // ValidFrom is the timestamp at which moment the command was created.
	Validity     time.Duration // Validity determines the point in time the command expires. Expired commands disappear almost immediately.
	IP           string        // IP is the client computer's IP the command is issued to.
	Content      interface{}   // Content is the command content, serialised and transmitted between server and client.
	SeenByClient bool          // SeenByClient is updated to true via RPC once the client has seen this command.
	ClientResult string        // ClientResult is updated via RPC once client has finished executing this command.
}

// IsValid returns true only if the command has not expired.
func (cmd *PendingCommand) IsValid() bool {
	return cmd.ValidFrom.Add(cmd.Validity).Unix() > time.Now().Unix()
}

/*
A key record that knows all about the encrypted file system, its mount point, and unlocking keys.
When stored on disk, the record resides in a file encoded in gob.
The binary encoding method is intentionally chosen to deter users from manually editing the files on disk.
*/
type Record struct {
	ID           string    // ID is assigned by KMIP server for the encryption key.
	Version      int       // Version is the version number of this record. Outdated records are automatically upgraded.
	CreationTime time.Time // CreationTime is the timestamp at which the record was created.
	Key          []byte    // Key is the disk encryption key if the key is not stored on an external KMIP server.

	UUID         string   // UUID is the block device UUID of the file system.
	MountPoint   string   // MountPoint is the location (directory) where this file system is expected to be mounted to.
	MountOptions []string // MountOptions is a string array of mount options specific to the file system.

	MaxActive        int // MaxActive is the maximum simultaneous number of online users (computers) for the key, or <=0 for unlimited.
	AliveIntervalSec int // AliveIntervalSec is interval in seconds that all key users (computers) should report they're online.
	AliveCount       int // AliveCount is number of times a key user (computer) can miss regular report and be considered offline.

	LastRetrieval   AliveMessage                // LastRetrieval is the computer who most recently successfully retrieved the key.
	AliveMessages   map[string][]AliveMessage   // AliveMessages are the most recent alive reports in IP - message array pairs.
	PendingCommands map[string][]PendingCommand // PendingCommands are some command to be periodcally polled by clients carrying the IP address (keys).
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

// RemoveDeadPendingCommands removes pending commands and results that were made 10x validity period in the past.
func (rec *Record) RemoveExpiredPendingCommands() {
	ipToDelete := make([]string, 0, 0)
	for ip, commands := range rec.PendingCommands {
		remainingCommands := make([]PendingCommand, 0, len(commands))
		for _, cmd := range commands {
			if cmd.IsValid() {
				remainingCommands = append(remainingCommands, cmd)
			}
		}
		if len(remainingCommands) > 0 {
			rec.PendingCommands[ip] = remainingCommands
		} else {
			ipToDelete = append(ipToDelete, ip)
		}
	}
	for _, ip := range ipToDelete {
		delete(rec.PendingCommands, ip)
	}
}

// AddPendingCommand stores a command associated to the input IP address, and clears expired pending commands along the way.
func (rec *Record) AddPendingCommand(ip string, cmd PendingCommand) {
	rec.RemoveExpiredPendingCommands()
	if _, found := rec.PendingCommands[ip]; !found {
		rec.PendingCommands[ip] = make([]PendingCommand, 0, 4)
	}
	rec.PendingCommands[ip] = append(rec.PendingCommands[ip], cmd)
}

// ClearPendingCommands removes all pending commands, and clears expired pending commands along the way.
func (rec *Record) ClearPendingCommands() {
	rec.PendingCommands = make(map[string][]PendingCommand)
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
	return fmt.Sprintf(`Timestamp="%d"%sIP="%s"%sHostname="%s"%sFileSystemUUID="%s"%sKMIPID="%s"%sMountPoint="%s"%sMountOptions="%s"`,
		rec.LastRetrieval.Timestamp, separator,
		rec.LastRetrieval.IP, separator,
		rec.LastRetrieval.Hostname, separator,
		rec.UUID, separator,
		rec.ID, separator,
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
