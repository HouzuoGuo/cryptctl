// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package command

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/keyserv"
	"github.com/HouzuoGuo/cryptctl/routine"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	SERVER_DAEMON      = "cryptctl-server"
	SERVER_CONFIG_PATH = "/etc/sysconfig/cryptctl-server"
	SERVER_GENTLS_PATH = "/etc/cryptctl/servertls"
	TIME_OUTPUT_FORMAT = "2006-01-02 15:04:05"
	MIN_PASSWORD_LEN   = 10
)

// Interactively read server password from terminal, then use the password to ping RPC server.
func ConnectToKeyServer(caFile, keyServer string) (client *keyserv.CryptClient, password string, err error) {
	sys.LockMem()
	serverAddr := keyServer
	port := keyserv.SRV_DEFAULT_PORT
	if portIdx := strings.LastIndex(keyServer, ":"); portIdx != -1 {
		portStr := keyServer[portIdx+1:]
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, "", fmt.Errorf("Port number is not a valid integer in \"%s\"", keyServer)
		}
		port = portInt
		serverAddr = keyServer[0:portIdx]
	}
	// Read custom CA file
	var customCA []byte
	if caFile != "" {
		caFileContent, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, "", fmt.Errorf("Failed to read custom CA file \"%s\" - %v", caFile, err)
		}
		customCA = caFileContent
	}
	// Initialise client and test connectivity with the server
	client, err = keyserv.NewCryptClient(serverAddr, port, customCA)
	if err != nil {
		return nil, "", err
	}
	password = sys.InputPassword(true, "", "Enter key server's password (no echo)")
	fmt.Fprintf(os.Stderr, "Establishing connection to %s on port %d...\n", serverAddr, port)
	if err := client.Ping(keyserv.PingRequest{Password: password}); err != nil {
		return nil, "", err
	}
	return
}

/*
Open key database from the location specified in sysconfig file.
If UUID is given, the database will only load a single record.
*/
func OpenKeyDB(recordUUID string) (*keydb.DB, error) {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to read configuratioon file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	dbDir := sysconf.GetString(keyserv.SRV_CONF_KEYDB_DIR, "")
	if dbDir == "" {
		return nil, errors.New("Key database directory is not configured. Is the server initialised?")
	}
	var db *keydb.DB
	if recordUUID == "" {
		db, err = keydb.OpenDB(dbDir)
	} else {
		db, err = keydb.OpenDBOneRecord(dbDir, recordUUID)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to open key database \"%s\" - %v", dbDir, err)
	}
	return db, nil
}

// Server - complete the initial setup.
func InitKeyServer() error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return fmt.Errorf("InitKeyServer: failed to read %s - %v", SERVER_CONFIG_PATH, err)
	}

	// Some of the mandatory questions will accept empty answers if a configuration already exists
	var reconfigure bool
	if sysconf.GetString(keyserv.SRV_CONF_PASS_HASH, "") != "" {
		reconfigure = true
		if !sys.InputBool(`You appear to have already initialised the configuration on this key server.
Would you like to re-configure it?`) {
			fmt.Println("OK, existing configuration is left untouched.")
			return nil
		}
	}
	fmt.Println("Please enter value for the following parameters, or leave blank to accept the default value.")

	// Ask for a new password and store its hash
	var pwd string
	pwdHint := ""
	if reconfigure {
		pwdHint = "*****"
	}
	for {
		pwd = sys.InputPassword(!reconfigure, pwdHint, "Access password (min. %d chars, no echo)", MIN_PASSWORD_LEN)
		if len(pwd) != 0 && len(pwd) < MIN_PASSWORD_LEN {
			fmt.Printf("\nPassword is too short, please enter a minimum of %d characters.\n", MIN_PASSWORD_LEN)
			continue
		}
		fmt.Println()
		confirmPwd := sys.InputPassword(!reconfigure, pwdHint, "Confirm access password (no echo)")
		fmt.Println()
		if confirmPwd == pwd {
			break
		} else {
			fmt.Println("Password does not match.")
			continue
		}
	}
	if pwd != "" {
		newSalt := keyserv.NewSalt()
		sysconf.Set(keyserv.SRV_CONF_PASS_SALT, hex.EncodeToString(newSalt[:]))
		newPwd := keyserv.HashPassword(newSalt, pwd)
		sysconf.Set(keyserv.SRV_CONF_PASS_HASH, hex.EncodeToString(newPwd[:]))
	}
	// Ask for TLS certificate and key, or generate a self-signed one if user wishes to.
	generateCert := false
	if reconfigure {
		// Server was previously initialised
		if tlsCert := sys.InputAbsFilePath(false,
			sysconf.GetString(keyserv.SRV_CONF_TLS_CERT, ""),
			"PEM-encoded TLS certificate or a certificate chain file"); tlsCert != "" {
			sysconf.Set(keyserv.SRV_CONF_TLS_CERT, tlsCert)
		}
	} else {
		// Propose to generate a self-signed certificate
		if tlsCert := sys.InputAbsFilePath(false, "", `PEM-encoded TLS certificate or a certificate chain file
(leave blank to auto-generate self-signed certificate)`); tlsCert == "" {
			generateCert = true
		} else {
			sysconf.Set(keyserv.SRV_CONF_TLS_CERT, tlsCert)
		}
	}
	if generateCert {
		certCommonName, hostIP := sys.GetHostnameAndIP()
		if certCommonName == "" {
			certCommonName = hostIP // if host name cannot be determined, simply use an IP address as common name
		}
		// Ask user for a preferred host name
		if preferredHostName := sys.Input(false, certCommonName, "Host name for the generated certificate"); preferredHostName != "" {
			certCommonName = preferredHostName
		}
		if err := os.MkdirAll(SERVER_GENTLS_PATH, 0700); err != nil {
			return fmt.Errorf("Failed to create directory \"%s\" for storing generated certificates - %v", SERVER_GENTLS_PATH, err)
		}
		// While openssl generates the certificate, print dots to stdout to show that program is busy.
		fmt.Println("Generating certificate...")
		opensslDone := make(chan bool, 1)
		go func() {
			for {
				select {
				case <-opensslDone:
					return
				case <-time.After(1 * time.Second):
					fmt.Print(".")
					os.Stdout.Sync()
				}
			}
		}()
		certPath := path.Join(SERVER_GENTLS_PATH, certCommonName+".crt")
		keyPath := path.Join(SERVER_GENTLS_PATH, certCommonName+".key")
		err := routine.GenerateSelfSignedCertificate(certCommonName, certPath, keyPath)
		opensslDone <- true
		if err != nil {
			return err
		}
		fmt.Printf(`
Self-signed certificate has been generated for host name "%s":
%s
%s

Important notes for client computers:
- They must have a copy of certificate file "%s" to communicate securely with this server.
- In cryptctl commands, the key server's host name must use "%s".
- When cryptctl commands ask for key server's CA, they must be given "/path/to/%s".
- Consult manual page cryptctl(8) section Communication Security for more information.

`, certCommonName, certPath, keyPath, path.Base(certPath), certCommonName, path.Base(certPath))
		// Point sysconfig values to the generated certificate
		sysconf.Set(keyserv.SRV_CONF_TLS_CERT, certPath)
		sysconf.Set(keyserv.SRV_CONF_TLS_KEY, keyPath)
	} else {
		// If certificate was specified, ask for its key file
		if tlsKey := sys.InputAbsFilePath(!reconfigure,
			sysconf.GetString(keyserv.SRV_CONF_TLS_KEY, ""),
			"PEM-encoded TLS certificate key that corresponds to the certificate"); tlsKey != "" {
			sysconf.Set(keyserv.SRV_CONF_TLS_KEY, tlsKey)
		}
	}

	// Walk through the remaining mandatory configuration keys
	if listenAddr := sys.Input(false,
		sysconf.GetString(keyserv.SRV_CONF_LISTEN_ADDR, ""),
		"IP address for the server to listen on (0.0.0.0 to listen on all network interfaces)"); listenAddr != "" {
		sysconf.Set(keyserv.SRV_CONF_LISTEN_ADDR, listenAddr)
	}
	if listenPort := sys.InputInt(false,
		sysconf.GetInt(keyserv.SRV_CONF_LISTEN_PORT, 0), 1, 65535,
		"TCP port number to listen on"); listenPort != 0 {
		sysconf.Set(keyserv.SRV_CONF_LISTEN_PORT, listenPort)
	}
	if keyDBDir := sys.InputAbsFilePath(true,
		sysconf.GetString(keyserv.SRV_CONF_KEYDB_DIR, ""),
		"Key database directory"); keyDBDir != "" {
		sysconf.Set(keyserv.SRV_CONF_KEYDB_DIR, keyDBDir)
	}
	// Walk through optional email settings
	fmt.Println("\nTo enable Email notifications, enter the following parameters:")
	if mta := sys.Input(false,
		sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, ""),
		"SMTP server name (not IP address) and port such as \"example.com:25\""); mta != "" {
		sysconf.Set(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, mta)
	}
	if sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, "") != "" {
		if fromAddr := sys.Input(false,
			sysconf.GetString(keyserv.SRV_CONF_MAIL_FROM_ADDR, ""),
			"Notification email's FROM address such as \"root@example.com\""); fromAddr != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_FROM_ADDR, fromAddr)
		}
		if recipients := sys.Input(false,
			sysconf.GetString(keyserv.SRV_CONF_MAIL_RECIPIENTS, ""),
			"Space-separated notification recipients such as \"admin@example.com\""); recipients != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RECIPIENTS, recipients)
		}
		if creationSubj := sys.Input(false,
			"",
			"Subject of key-creation notification email"); creationSubj != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_CREATION_SUBJ, creationSubj)
		}
		if creationText := sys.Input(false,
			"",
			"Text of key-creation notification email"); creationText != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_CREATION_TEXT, creationText)
		}
		if retrievalSubj := sys.Input(false,
			"",
			"Subject of key-retrieval notification email"); retrievalSubj != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RETRIEVAL_SUBJ, retrievalSubj)
		}
		if retrievalText := sys.Input(false,
			"",
			"Text of key-retrieval notification email"); retrievalText != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RETRIEVAL_TEXT, retrievalText)
		}
	}
	if err := ioutil.WriteFile(SERVER_CONFIG_PATH, []byte(sysconf.ToText()), 0600); err != nil {
		return fmt.Errorf("Failed to save settings into %s - %v", SERVER_CONFIG_PATH, err)
	}
	// Restart server
	fmt.Println("\nSettings have been saved successfully!")
	var start bool
	if sys.SystemctlIsRunning(SERVER_DAEMON) {
		start = sys.InputBool("Would you like to restart key server (%s) to apply the new settings?", SERVER_DAEMON)
	} else {
		start = sys.InputBool("Would you like to start key server (%s) now?", SERVER_DAEMON)
	}
	if !start {
		return nil
	}
	// (Re)start server and then display the PID in output.
	if err := sys.SystemctlEnableRestart(SERVER_DAEMON); err != nil {
		return fmt.Errorf("%v", err)
	}
	// Wait up to 5 seconds for server daemon to start
	for i := 0; i < 5; i++ {
		if pid := sys.SystemctlGetMainPID(SERVER_DAEMON); pid != 0 {
			// After server appears to be running, monitor it for 3 more seconds to make sure it stays running.
			for j := 0; j < 3; j++ {
				if pid := sys.SystemctlGetMainPID(SERVER_DAEMON); pid == 0 {
					// Server went down after it had started
					return fmt.Errorf("Startup failed. Please inspect the output of \"systemctl status %s\".\n", SERVER_DAEMON)
				}
				time.Sleep(1 * time.Second)
			}
			fmt.Printf("Key server is now running (PID %d).\n", pid)
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	// Server failed to start in time
	fmt.Printf("Startup failed. Please inspect the output of \"systemctl status %s\".\n", SERVER_DAEMON)
	return nil
}

// Server - run key service daemon.
func KeyRPCDaemon() error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return fmt.Errorf("Failed to read configuratioon file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	srvConf := keyserv.CryptServiceConfig{}
	if err := srvConf.ReadFromSysconfig(sysconf); err != nil {
		return fmt.Errorf("Failed to load configuration from file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	mailer := keyserv.Mailer{}
	mailer.ReadFromSysconfig(sysconf)
	srv, err := keyserv.NewCryptServer(srvConf, mailer)
	if err != nil {
		return fmt.Errorf("Failed to initialise server - %v", err)
	}
	// Print helpful information regarding server's initial setup and mailer configuration
	if nonFatalErr := srv.CheckInitialSetup(); nonFatalErr != nil {
		log.Print("Key server is not confiured yet. Please run `cryptctl init-server` to complete initial setup.")
	}
	if nonFatalErr := mailer.ValidateConfig(); nonFatalErr == nil {
		log.Printf("Email notifications will be sent from %s to %v via %s",
			mailer.FromAddress, mailer.Recipients, mailer.AgentAddressPort)
	} else {
		log.Printf("Email notifications are not enabled: %v", nonFatalErr)
	}
	log.Printf("GOMAXPROCS is currently: %d", runtime.GOMAXPROCS(-1))
	// Start the server loop, which will block until the server quits.
	if err := srv.ListenRPC(); err != nil {
		return fmt.Errorf("Failed to listen for connections: %v", err)
	}
	return nil
}

// Server - print all key records sorted according to last access.
func ListKeys() error {
	db, err := OpenKeyDB("")
	if err != nil {
		return err
	}
	recList := db.List()
	fmt.Printf("Total: %d records (date and time are in zone %s)\n", len(recList), time.Now().Format("MST"))
	// Print mount point last, making output possible to be parsed by a program
	// Max field length: 15 (IP), 19 (IP When), 36 (UUID), 9 (Max Active), 9 (Current Active) last field (mount point)
	fmt.Println("Used By         When                UUID                                 Max.Users Num.Users Mount Point")
	for _, rec := range recList {
		outputTime := time.Unix(rec.LastRetrieval.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
		rec.RemoveDeadHosts()
		fmt.Printf("%-15s %-19s %-36s %-9s %-9s %s\n", rec.LastRetrieval.IP, outputTime, rec.UUID,
			strconv.Itoa(rec.MaxActive), strconv.Itoa(len(rec.AliveMessages)), rec.MountPoint)
	}
	return nil
}

// Server - let user edit key details such as mount point and mount options
func EditKey(uuid string) error {
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec := db.RecordsByUUID[uuid]
	// Similar to the encryption routine, ask user all the configuration questions.
	newMountPoint := sys.Input(false, rec.MountPoint, "Mount point")
	if newMountPoint != "" {
		rec.MountPoint = newMountPoint
	}
	newOptions := sys.Input(false, strings.Join(rec.MountOptions, ","), "Mount options (space-separated)")
	if newOptions != "" {
		rec.MountOptions = strings.Split(newOptions, ",")
	}
	newMaxActive := sys.InputInt(false, rec.MaxActive, 1, 99999, MSG_ASK_MAX_ACTIVE)
	if newMaxActive != 0 {
		rec.MaxActive = newMaxActive
	}
	newAliveTimeout := sys.InputInt(false, rec.AliveIntervalSec*rec.AliveCount, DEFUALT_ALIVE_TIMEOUT, 3600*24*7, MSG_ASK_ALIVE_TIMEOUT)
	if newAliveTimeout != 0 {
		roundedAliveTimeout := newAliveTimeout / routine.REPORT_ALIVE_INTERVAL_SEC * routine.REPORT_ALIVE_INTERVAL_SEC
		if roundedAliveTimeout != newAliveTimeout {
			fmt.Printf(MSG_ALIVE_TIMEOUT_ROUNDED, roundedAliveTimeout)
		}
		rec.AliveCount = roundedAliveTimeout / routine.REPORT_ALIVE_INTERVAL_SEC
	}
	// Write record file and restart server to let it reload all records into memory
	if err := db.Upsert(rec); err != nil {
		return fmt.Errorf("Failed to update record - %v", err)
	}
	fmt.Println("Record has been updated successfully.")
	if sys.SystemctlIsRunning(SERVER_DAEMON) {
		fmt.Println("Restarting key server...")
		if err := sys.SystemctlEnableRestart(SERVER_DAEMON); err != nil {
			return err
		}
		fmt.Println("All done.")
	}
	return nil
}

// Server - show key record details but hide key content
func ShowKey(uuid string) error {
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec := db.RecordsByUUID[uuid]
	rec.RemoveDeadHosts()
	fmt.Printf("%-34s%s\n", "UUID", rec.UUID)
	fmt.Printf("%-34s%s\n", "Mount Point", rec.MountPoint)
	fmt.Printf("%-34s%s\n", "Mount Options", rec.GetMountOptionStr())
	fmt.Printf("%-34s%d\n", "Maximum Computers", rec.MaxActive)
	fmt.Printf("%-34s%d\n", "Computer Keep-Alive Timeout (sec)", rec.AliveCount*rec.AliveIntervalSec)
	fmt.Printf("%-34s%s (%s)\n", "Last Retrieved By", rec.LastRetrieval.IP, rec.LastRetrieval.Hostname)
	outputTime := time.Unix(rec.LastRetrieval.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
	fmt.Printf("%-34s%s\n", "Last Retrieved On", outputTime)
	fmt.Printf("%-34s%d\n", "Current Active Computers", len(rec.AliveMessages))
	if len(rec.AliveMessages) > 0 {
		// Print alive message's details from each computer
		for _, msgs := range rec.AliveMessages {
			for _, msg := range msgs {
				outputTime := time.Unix(msg.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
				fmt.Printf("%-34s%s %s (%s)\n", "", outputTime, msg.IP, msg.Hostname)
			}
		}
	}
	return nil
}
