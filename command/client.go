// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package command

import (
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/keyserv"
	"github.com/HouzuoGuo/cryptctl/routine"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DEFUALT_ALIVE_TIMEOUT   = 3 * routine.REPORT_ALIVE_INTERVAL_SEC
	AUTO_UNLOCK_DAEMON      = "cryptctl-auto-unlock@"
	CLIENT_CONFIG_PATH      = "/etc/sysconfig/cryptctl-client"
	ONLINE_UNLOCK_RETRY_SEC = 24 * 3600
	MSG_ASK_HOSTNAME        = "Key server's host name"
	MSG_ASK_PORT            = "Key server's port number"
	MSG_ASK_CA              = "(Optional) PEM-encoded CA certificate of key server"
	MSG_ASK_CLIENT_CERT     = "If key server will validate client identity, enter path to PEM-encoded client certificate"
	MSG_ASK_CLIENT_CERT_KEY = "If key server will validate client identity, enter path to PEM-encoded client key"
	MSG_ASK_DIFF_HOST       = `Previously, this computer used "%s" as its key server; now you wish to use "%s".
Only a single key server can be used to unlock all encrypted disks on this computer.
Do you wish to proceed and switch to the new key server?`
	MSG_ASK_SRC_DIR           = "Path of directory to be encrypted"
	MSG_ASK_ENC_DISK          = "Path of disk partition (/dev/sdXXX) that will hold the directory after encryption"
	MSG_ASK_MAX_ACTIVE        = "How many computers can use the encrypted disk simultaneously"
	MSG_ASK_ALIVE_TIMEOUT     = "If the key server does not hear from this computer for so many seconds, other computers will be allowed to use the key"
	MSG_ASK_KEYREC_PATH       = "Path of the key record"
	MSG_ASK_MOUNT             = "Where should the file system be mounted"
	MSG_ASK_MOUNT_OPT         = "Mount options (comma-separated)"
	MSG_ALIVE_TIMEOUT_ROUNDED = "The number of seconds has been rounded to %d.\n"
	MSG_ENC_SEQUENCE          = `
Please take note to:
  - Avoid touching the encrypted disk/directory until the operation completes.
  - Ignore desktop prompts for entering disk password.

The encryption sequence will carry out the following tasks:
  1. Completely erase disk "%s" and install encryption key on it.
  2. Copy data from "%s" into the disk.
  3. Announce the encrypted disk to key server.

`
	MSG_E_CANCELLED           = "Operation is cancelled."
	MSG_E_SAVE_SYSCONF        = "Failed to save settings into %s - %v"
	MSG_ASK_PROCEED           = "Please double check the details and type Yes to proceed"
	MSG_E_READ_FILE           = "Failed to read file \"%s\" - %v"
	MSG_E_BAD_KEYREC          = "Failed to read record content (is the file damaged?) - %v"
	MSG_UNLOCK_IS_NOP         = "cryptctl is doing nothing because client configuration is empty"
	MSG_ERASE_UUID            = "UUID of the file system to erase"
	MSG_ERASE_UUID_AGAIN      = "Warning! Data on \"%s\" will be irreversibly lost, type the UUID once again to confirm"
	MSG_E_ERASE_UUID_MISMATCH = "UUID input does not match."
	MSG_E_ERASE_NO_CONF       = "The erase operation must contact key server in order to erase a key, but cryptctl configuration is empty."

	ClientDaemonService = "cryptctl-client"
)

// Prompt user to enter key server's CA file, host name, and port. Defaults are provided by existing configuration.
func PromptForKeyServer() (sysconf *sys.Sysconfig, caFile, certFile, certKeyFile, host string, port int, err error) {
	sysconf, err = sys.ParseSysconfigFile(CLIENT_CONFIG_PATH, true)
	if err != nil {
		return
	}
	defaultHost := sysconf.GetString(keyserv.CLIENT_CONF_HOST, "")
	if host = sys.Input(true, defaultHost, MSG_ASK_HOSTNAME); host == "" {
		host = defaultHost
	}
	defaultPort := sysconf.GetInt(keyserv.CLIENT_CONF_PORT, keyserv.SRV_DEFAULT_PORT)
	if port = sys.InputInt(true, defaultPort, 1, 65535, MSG_ASK_PORT); port == 0 {
		port = defaultPort
	}
	defaultCAFile := sysconf.GetString(keyserv.CLIENT_CONF_CA, "")
	if caFile = sys.InputAbsFilePath(false, defaultCAFile, MSG_ASK_CA); caFile == "" {
		caFile = defaultCAFile
	}
	defaultCertFile := sysconf.GetString(keyserv.CLIENT_CONF_CERT, "")
	if certFile = sys.InputAbsFilePath(false, defaultCertFile, MSG_ASK_CLIENT_CERT); certFile == "" {
		certFile = defaultCertFile
	}
	if certFile != "" {
		defaultCertKeyFile := sysconf.GetString(keyserv.CLIENT_CONF_CERT_KEY, "")
		if certKeyFile = sys.InputAbsFilePath(false, defaultCertKeyFile, MSG_ASK_CLIENT_CERT_KEY); certKeyFile == "" {
			certKeyFile = defaultCertKeyFile
		}
	}
	return
}

// CLI command: set up encryption on a file system using a randomly generated key and upload the key to key server.
func EncryptFS() error {
	sys.LockMem()

	// Prompt for connection details
	sysconf, caFile, certFile, certKeyFile, host, port, err := PromptForKeyServer()
	if err != nil {
		return err
	}
	storedHost := sysconf.GetString(keyserv.CLIENT_CONF_HOST, "")
	if storedHost != "" && host != storedHost {
		if !sys.InputBool(false, MSG_ASK_DIFF_HOST, storedHost, host) {
			return errors.New(MSG_E_CANCELLED)
		}
	}

	// Check server connectivity before commencing encryption
	client, password, err := ConnectToKeyServer(caFile, certFile, certKeyFile, fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}

	// Ask about encrypted disks
	srcDir := sys.InputAbsFilePath(true, "", MSG_ASK_SRC_DIR)
	srcDir = filepath.Clean(srcDir)
	encDisk := sys.InputAbsFilePath(true, "", MSG_ASK_ENC_DISK)
	encDisk = filepath.Clean(encDisk)
	maxActive := sys.InputInt(true, 1, 1, 99999, MSG_ASK_MAX_ACTIVE)
	if maxActive == 0 {
		maxActive = 1
	}
	aliveTimeout := sys.InputInt(true, DEFUALT_ALIVE_TIMEOUT, DEFUALT_ALIVE_TIMEOUT, 3600*24*7, MSG_ASK_ALIVE_TIMEOUT)
	if aliveTimeout == 0 {
		aliveTimeout = DEFUALT_ALIVE_TIMEOUT
	}
	roundedAliveTimeout := aliveTimeout / routine.REPORT_ALIVE_INTERVAL_SEC * routine.REPORT_ALIVE_INTERVAL_SEC
	if roundedAliveTimeout != aliveTimeout {
		fmt.Printf(MSG_ALIVE_TIMEOUT_ROUNDED, roundedAliveTimeout)
	}

	// Check pre-conditions for encryption
	if err := routine.EncryptFSPreCheck(srcDir, encDisk); err != nil {
		return err
	}

	// Prompt user for confirmation and then proceed
	fmt.Printf(MSG_ENC_SEQUENCE, encDisk, srcDir)
	if !sys.InputBool(false, MSG_ASK_PROCEED) {
		return errors.New(MSG_E_CANCELLED)
	}
	// Alive-report interval is hard coded for now until there is a very good reason to change it
	uuid, err := routine.EncryptFS(os.Stdout, client, password, srcDir, encDisk, maxActive,
		routine.REPORT_ALIVE_INTERVAL_SEC, roundedAliveTimeout/routine.REPORT_ALIVE_INTERVAL_SEC)
	if err != nil {
		return err
	}

	// Put latest key server details into client configuration file
	sysconf.Set(keyserv.CLIENT_CONF_HOST, host)
	sysconf.Set(keyserv.CLIENT_CONF_PORT, strconv.Itoa(port))
	sysconf.Set(keyserv.CLIENT_CONF_CA, caFile)
	sysconf.Set(keyserv.CLIENT_CONF_CERT, certFile)
	sysconf.Set(keyserv.CLIENT_CONF_CERT_KEY, certKeyFile)
	if err := ioutil.WriteFile(CLIENT_CONFIG_PATH, []byte(sysconf.ToText()), 0600); err != nil {
		return fmt.Errorf(MSG_E_SAVE_SYSCONF, CLIENT_CONFIG_PATH, err)
	}

	// Activate systemd service for the now encrypted disk so that alive messages are sent
	if err := sys.SystemctlStart(AUTO_UNLOCK_DAEMON + uuid); err != nil {
		return fmt.Errorf("Failed to start background daemon that reports disk status - %v", err)
	}
	// Activate and enable client daemon that polls for pending messages
	if err := sys.SystemctlEnableStart(ClientDaemonService); err != nil {
		return fmt.Errorf("Failed to start cryptctl client daemon - %v", err)
	}
	return nil
}

// Sub-command: forcibly unlock all file systems that have their keys on a key server.
func ManOnlineUnlockFS() error {
	sys.LockMem()
	_, caFile, certFile, certKeyFile, host, port, err := PromptForKeyServer()
	if err != nil {
		return err
	}
	client, password, err := ConnectToKeyServer(caFile, certFile, certKeyFile, fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	return routine.ManOnlineUnlockFS(os.Stdout, client, password)
}

// Sub-command: unlock a single file systems using a key record file.
func ManOfflineUnlockFS() error {
	sys.LockMem()
	keyRecordPath := sys.Input(true, "", MSG_ASK_KEYREC_PATH)
	content, err := ioutil.ReadFile(keyRecordPath)
	if err != nil {
		return fmt.Errorf(MSG_E_READ_FILE, keyRecordPath, err)
	}
	rec := keydb.Record{}
	if err := rec.Deserialise(content); err != nil {
		return fmt.Errorf(MSG_E_BAD_KEYREC, err)
	}
	fmt.Printf("Input key record:\n%s\n\n", rec.FormatAttrs("\n"))
	if newMountPoint := sys.Input(false, rec.MountPoint, MSG_ASK_MOUNT); newMountPoint != "" {
		rec.MountPoint = newMountPoint
	}
	if newMountOptions := sys.Input(false, rec.GetMountOptionStr(), MSG_ASK_MOUNT_OPT); newMountOptions != "" {
		rec.MountOptions = strings.Split(newMountOptions, ",")
	}
	return routine.UnlockFS(os.Stderr, rec, 3)
}

/*
Sub-command: contact key server to retrieve encryption key to unlock a single file system, then continuously send alive
reports to server to indicate that computer is still holding onto the encrypted disk.
Block caller until the program quits or server rejects this computer.
*/
func AutoOnlineUnlockFS(uuid string) error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(CLIENT_CONFIG_PATH, false)
	if err != nil {
		return err
	}
	if sysconf.GetString(keyserv.CLIENT_CONF_HOST, "") == "" {
		fmt.Println(MSG_UNLOCK_IS_NOP)
		return nil
	}
	client, err := keyserv.NewCryptClientFromSysconfig(sysconf)
	if err != nil {
		return err
	}
	if err := routine.AutoOnlineUnlockFS(os.Stdout, client, uuid, ONLINE_UNLOCK_RETRY_SEC); err != nil {
		return err
	}
	return routine.ReportAlive(os.Stderr, client, uuid)
}

/*
Sub-command: erase encryption headers for the encrypted disk, so that its content becomes irreversibly lost.
*/
func EraseKey() error {
	sys.LockMem()
	// Establish connection to key server
	sysconf, err := sys.ParseSysconfigFile(CLIENT_CONFIG_PATH, false)
	if err != nil {
		return err
	}
	host := sysconf.GetString(keyserv.CLIENT_CONF_HOST, "")
	if host == "" {
		return errors.New(MSG_E_ERASE_NO_CONF)
	}
	port := sysconf.GetInt(keyserv.CLIENT_CONF_PORT, 3737)
	if port == 0 {
		return errors.New(MSG_E_ERASE_NO_CONF)
	}
	caFile := sysconf.GetString(keyserv.CLIENT_CONF_CA, "")
	client, password, err := ConnectToKeyServer(
		caFile,
		sysconf.GetString(keyserv.CLIENT_CONF_CERT, ""),
		sysconf.GetString(keyserv.CLIENT_CONF_CERT_KEY, ""),
		fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	// Ask for the UUID to wipe and proceed
	uuid := sys.Input(true, "", MSG_ERASE_UUID)
	confirmUUID := sys.Input(true, "", MSG_ERASE_UUID_AGAIN, uuid)
	if confirmUUID != uuid {
		return errors.New(MSG_E_ERASE_UUID_MISMATCH)
	}
	if err := routine.EraseKey(os.Stdout, client, password, uuid); err != nil {
		return err
	}
	return nil
}

/*
ClientDaemon runs the main routine of "client-daemon" sub-command.
The routine primarily polls for pending commands and execute them.
*/
func ClientDaemon() error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(CLIENT_CONFIG_PATH, false)
	if err != nil {
		return err
	}
	if sysconf.GetString(keyserv.CLIENT_CONF_HOST, "") == "" {
		fmt.Println(MSG_UNLOCK_IS_NOP)
		return nil
	}
	client, err := keyserv.NewCryptClientFromSysconfig(sysconf)
	if err != nil {
		return err
	}
	log.Printf("Going to poll for commands from server %s every 30 seconds.", client.Address)
	for {
		time.Sleep(30 * time.Second)

		devs := fs.GetBlockDevices()
		uuids := make([]string, 0, len(devs))
		for _, dev := range devs {
			if dev.UUID != "" {
				uuids = append(uuids, dev.UUID)
			}
		}

		resp, err := client.PollCommand(keyserv.PollCommandReq{UUIDs: uuids})
		if err != nil {
			log.Printf("Failed to poll for pending commands: %v", err)
			continue
		}
		for uuid, cmds := range resp.Commands {
			for _, cmd := range cmds {
				if cmd.IsValid() {
					log.Printf("Going to execute command %+v", cmd)
					ExecutePendingCommand(client, uuid, cmd)
				} else {
					log.Printf("Ignoring expired command: %+v\n", cmd)
				}
			}
		}

	}
}

/*
UmountCryptDev un-mounts and closes the crypt block device associated with the block device specified in UUID.
Returns human-readable result text.
*/
func UmountCryptDev(uuid string) string {
	/*
		First steps should umount and close the disk.
		At very last, if no errors are encountered, stop reporting alive-messages.
	*/
	devs := fs.GetBlockDevices()
	underlyingDev, found := devs.GetByCriteria(uuid, "", "", "", "", "", "")
	if !found {
		return "The disk disappeared from system"
	}
	cryptDev, found := devs.GetByCriteria("", "", "crypt", "", "", underlyingDev.Name, "")
	if !found {
		return "The disk is not unlocked to begin with"
	}
	if cryptDev.MountPoint == "" {
		return "The disk is not mounted to begin with"
	}
	time.Sleep(3 * time.Second)
	log.Printf("Umount %s ...", cryptDev.MountPoint)
	if err := fs.Umount(cryptDev.MountPoint); err != nil {
		return fmt.Sprintf("Failed to umount encrypted device - %v", err)
	}
	time.Sleep(3 * time.Second)
	log.Printf("Closing down %s ...", cryptDev.Path)
	if err := fs.CryptClose(cryptDev.Path); err != nil {
		return fmt.Sprintf("Failed to close encrypted device - %v", err)
	}
	serviceName := AUTO_UNLOCK_DAEMON + uuid
	if err := sys.SystemctlStop(AUTO_UNLOCK_DAEMON + uuid); err != nil {
		return fmt.Sprintf("failed to stop service %s - %v", serviceName, err)
	}
	return "Success"
}

/*
ExecutePendingCommand is called by client daemon to execute a freshly polled pending command.
Execution result is logged into
*/
func ExecutePendingCommand(client *keyserv.CryptClient, uuid string, cmd keydb.PendingCommand) {
	result := "Success"
	if cmd.Content == PendingCommandMount {
		// Mounting an already mounted disk will result in a failure and no other negative consequence
		if err := sys.SystemctlStart(AUTO_UNLOCK_DAEMON + uuid); err != nil {
			result = fmt.Sprintf("Failed to start background daemon that reports disk status - %v", err)
		}
	} else if cmd.Content == PendingCommandUmount {
		// Similar to mount, umount a disk that is not mounted is a failure and results in no other negative consequence.
		result = UmountCryptDev(uuid)
	} else {
		result = fmt.Sprintf("Client does not understand command \"%v\"", cmd.Content)
	}
	log.Printf("ExecutePendingCommand: result is %s", result)
	if err := client.SaveCommandResult(keyserv.SaveCommandResultReq{
		UUID:           uuid,
		CommandContent: cmd.Content,
		Result:         result,
	}); err != nil {
		log.Printf("ExecutePendingCommand: failed to save command result - %v", err)
	}
	return
}
