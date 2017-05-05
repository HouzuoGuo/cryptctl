// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/sys"
	"log"
	"net"
	"net/rpc"
	"os"
	"path"
	"reflect"
	"strings"
	"time"
)

const (
	LEN_PASS_SALT          = 64   // length of random salt to go with each password
	LEN_SHUTDOWN_CHALLENGE = 64   // length of the random challenge that must be verified in order to shut down server
	SRV_DEFAULT_PORT       = 3737 // default port for the key server to listen on

	SRV_CONF_PASS_HASH           = "AUTH_PASSWORD_HASH"
	SRV_CONF_PASS_SALT           = "AUTH_PASSWORD_SALT"
	SRV_CONF_TLS_CERT            = "TLS_CERT_PEM"
	SRV_CONF_TLS_KEY             = "TLS_CERT_KEY_PEM"
	SRV_CONF_LISTEN_ADDR         = "LISTEN_ADDRESS"
	SRV_CONF_LISTEN_PORT         = "LISTEN_PORT"
	SRV_CONF_KEYDB_DIR           = "KEY_DB_DIR"
	SRV_CONF_MAIL_CREATION_SUBJ  = "EMAIL_KEY_CREATION_SUBJECT"
	SRV_CONF_MAIL_CREATION_TEXT  = "EMAIL_KEY_CREATION_GREETING"
	SRV_CONF_MAIL_RETRIEVAL_SUBJ = "EMAIL_KEY_RETRIEVAL_SUBJECT"
	SRV_CONF_MAIL_RETRIEVAL_TEXT = "EMAIL_KEY_RETRIEVAL_GREETING"

	SRV_CONF_KMIP_SERVER_HOST = "KMIP_SERVER_HOST"
	SRV_CONF_KMIP_SERVER_PORT = "KMIP_SERVER_PORT"
	SRV_CONF_KMIP_SERVER_USER = "KMIP_SERVER_USER"
	SRV_CONF_KMIP_SERVER_PASS = "KMIP_SERVER_PASS"
)

var PkgInGopath = path.Join(path.Join(os.Getenv("GOPATH"), "/src/github.com/HouzuoGuo/cryptctl")) // this package in gopath

func GetDefaultKeySvcConf() *sys.Sysconfig {
	defConf, err := sys.ParseSysconfigFile(path.Join(PkgInGopath, "ospackage/etc/sysconfig/cryptctl-server"), false)
	if err != nil {
		panic(err)
	}
	return defConf
}

// Return a newly generated salt for hasing passwords.
func NewSalt() (ret [LEN_PASS_SALT]byte) {
	if _, err := rand.Read(ret[:]); err != nil {
		panic(fmt.Errorf("NewSalt: failed to read from random source - %v", err))
	}
	return
}

// Compute a salted password hash using SHA512 method.
func HashPassword(salt [LEN_PASS_SALT]byte, plainText string) [sha512.Size]byte {
	plainBytes := []byte(plainText)
	// saltedBytes = salt + plainBytes
	saltedBytes := make([]byte, LEN_PASS_SALT+len(plainBytes))
	copy(saltedBytes[0:LEN_PASS_SALT], salt[:])
	copy(saltedBytes[LEN_PASS_SALT:], plainBytes)
	// hash = SHA512Digest(saltedBytes)
	return sha512.Sum512(saltedBytes)
}

// Configuration for RPC server.
type CryptServiceConfig struct {
	PasswordHash         [sha512.Size]byte   // password hash (salted) that authenticates incoming requests
	PasswordSalt         [LEN_PASS_SALT]byte // password hash salt
	CertPEM              string              // path to PEM-encoded TLS certificate
	KeyPEM               string              // path to PEM-encoded TLS certificate key
	Address              string              // address of the network interface to listen on
	Port                 int                 // port to listen on
	KeyDBDir             string              // key database directory
	KeyCreationSubject   string              // subject of the notification email sent by key creation request
	KeyCreationGreeting  string              // greeting of the notification email sent by key creation request
	KeyRetrievalSubject  string              // subject of the notification email sent by key retrieval request
	KeyRetrievalGreeting string              // greeting of the notification email sent by key retrieval request
	KMIPHost             string              // optional KMIP server host
	KMIPPort             int                 // optional KMIP server port
	KMIPUser             string              // optional KMIP service access user
	KMIPPass             string              // optional KMIP service access password
}

// Preliminarily validate configuration and report error.
func (conf *CryptServiceConfig) Validate() error {
	if err := fs.FileContains(conf.CertPEM, "CERTIFICATE"); err != nil {
		return fmt.Errorf("Validate: TLS certificate file - %v", err)
	} else if err := fs.FileContains(conf.KeyPEM, "KEY"); err != nil {
		return fmt.Errorf("Validate: TLS certificate key file - %v", err)
	} else if conf.Address == "" {
		return errors.New("Validate: network address to listen on is empty")
	} else if conf.Port == 0 {
		return errors.New("Validate: network port to listen on is not specified")
	} else if !strings.HasPrefix(conf.KeyDBDir, "/") {
		return fmt.Errorf("Validate: key database directory \"%s\" should be an absolute path", conf.KeyDBDir)
	}
	return nil
}

// Read key server configuration from a sysconfig file.
func (conf *CryptServiceConfig) ReadFromSysconfig(sysconf *sys.Sysconfig) error {
	passwordHash, err := hex.DecodeString(sysconf.GetString(SRV_CONF_PASS_HASH, ""))
	if err != nil {
		return fmt.Errorf("NewCryptService: malformed value in key %s", SRV_CONF_PASS_HASH)
	}
	passwordSalt, err := hex.DecodeString(sysconf.GetString(SRV_CONF_PASS_SALT, ""))
	if err != nil {
		return fmt.Errorf("NewCryptService: malformed value in key %s", SRV_CONF_PASS_SALT)
	}
	copy(conf.PasswordHash[:], passwordHash)
	copy(conf.PasswordSalt[:], passwordSalt)

	conf.CertPEM = sysconf.GetString(SRV_CONF_TLS_CERT, "")
	conf.KeyPEM = sysconf.GetString(SRV_CONF_TLS_KEY, "")
	conf.Address = sysconf.GetString(SRV_CONF_LISTEN_ADDR, "0.0.0.0")
	conf.Port = sysconf.GetInt(SRV_CONF_LISTEN_PORT, SRV_DEFAULT_PORT)

	conf.KeyDBDir = sysconf.GetString(SRV_CONF_KEYDB_DIR, "/var/lib/cryptctl/keydb")

	conf.KeyCreationSubject = sysconf.GetString(SRV_CONF_MAIL_CREATION_SUBJ, "A new file system has been encrypted")
	conf.KeyCreationGreeting = sysconf.GetString(SRV_CONF_MAIL_CREATION_TEXT, "The key server now has encryption key for the following file system:")
	conf.KeyRetrievalSubject = sysconf.GetString(SRV_CONF_MAIL_RETRIEVAL_SUBJ, "An encrypted file system has been accessed")
	conf.KeyRetrievalGreeting = sysconf.GetString(SRV_CONF_MAIL_RETRIEVAL_TEXT, "The key server has sent the following encryption key to allow access to its file systems:")

	conf.KMIPHost = sysconf.GetString(SRV_CONF_KMIP_SERVER_HOST, "")
	conf.KMIPPort = sysconf.GetInt(SRV_CONF_KMIP_SERVER_PORT, 0)
	conf.KMIPUser = sysconf.GetString(SRV_CONF_KMIP_SERVER_USER, "")
	conf.KMIPPass = sysconf.GetString(SRV_CONF_KMIP_SERVER_PASS, "")
	return conf.Validate()
}

// RPC and KMIP server for accessing encryption keys.
type CryptServer struct {
	Config            CryptServiceConfig // service configuration
	Mailer            *Mailer            // mail notification sender
	KeyDB             *keydb.DB          // encryption key database
	TLSConfig         *tls.Config        // TLS certificate chain and private key
	Listener          net.Listener       // listener for client connections
	ShutdownChallenge []byte             // a random secret that must be verified for incoming shutdown requests
}

// Initialise an RPC server from sysconfig file text.
func NewCryptServer(config CryptServiceConfig, mailer Mailer) (srv *CryptServer, err error) {
	if err = config.Validate(); err != nil {
		return
	}
	srv = &CryptServer{
		Config:    config,
		Mailer:    &mailer,
		TLSConfig: new(tls.Config),
	}
	srv.KeyDB, err = keydb.OpenDB(config.KeyDBDir)
	if err != nil {
		return
	}
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(config.CertPEM, config.KeyPEM)
	// Shutdown challenge is an array of random bytes
	srv.ShutdownChallenge = make([]byte, LEN_SHUTDOWN_CHALLENGE)
	if _, err = rand.Read(srv.ShutdownChallenge); err != nil {
		return
	}
	return
}

// Start RPC server and block until the server listener is told to shut down.
func (srv *CryptServer) ListenRPC() (err error) {
	// It is not necessary to validate initial server setup, because ping should always work.
	srv.Listener, err = tls.Listen("tcp", fmt.Sprintf("%s:%d", srv.Config.Address, srv.Config.Port), srv.TLSConfig)
	if err != nil {
		return fmt.Errorf("ListenRPC: failed to listen on %s:%d - %v", srv.Config.Address, srv.Config.Port, err)
	}
	log.Printf("ListenRPC: listening on %s:%d using TLS certficate \"%s\"", srv.Config.Address, srv.Config.Port, srv.Config.CertPEM)
	for {
		incoming, err := srv.Listener.Accept()
		if err != nil {
			log.Printf("ListenRPC: quit now - %v", err)
			return nil
		}
		// The connection is served by a dedicated RPC server instance
		go func(conn net.Conn) {
			srv.ServeConn(conn)
			conn.Close()
		}(incoming)
	}
	return nil
}

/*
Check that password parameters are present, which means the initial setup of the server has been completed.
Return nil if all OK.
Return an error with description text if password parameters are incomplete.
*/
func (srv *CryptServer) CheckInitialSetup() error {
	// Make sure the password parameters have correct length
	zero1 := true
	for _, b := range srv.Config.PasswordHash {
		if b != 0 {
			zero1 = false
		}
	}
	zero2 := true
	for _, b := range srv.Config.PasswordSalt {
		if b != 0 {
			zero2 = false
		}
	}
	if zero1 || zero2 {
		return errors.New("CheckInitialSetup: server configuration has not yet been initialised")
	}
	return nil
}

// Validate a password against stored hash.
func (srv *CryptServer) ValidatePassword(plainText string) error {
	// Fail straight away if server setup is missing
	if err := srv.CheckInitialSetup(); err != nil {
		return err
	}
	hashInput := HashPassword(srv.Config.PasswordSalt, plainText)
	if subtle.ConstantTimeCompare(hashInput[:], srv.Config.PasswordHash[:]) != 1 {
		return errors.New("ValidatePassword: password is incorrect")
	}
	return nil
}

// Create an RPC service object that handles requests from an incoming connection.
func (srv *CryptServer) ServeConn(incoming net.Conn) (rpcSvc *rpc.Server) {
	rpcSvc = rpc.NewServer()
	remoteIP := strings.Split(incoming.RemoteAddr().String(), ":")
	if err := rpcSvc.Register(&CryptServiceConn{RemoteAddr: remoteIP[0], Svc: srv}); err != nil {
		log.Panicf("ServeConn: failed to register RPC service - %v", err)
	}
	rpcSvc.ServeConn(incoming)
	return
}

// Serve RPC routines for key creation/retrieval services.
type CryptServiceConn struct {
	RemoteAddr string
	Svc        *CryptServer
}

var RPCObjNameFmt = reflect.TypeOf(CryptServiceConn{}).Name() + ".%s" // for constructing RPC function name in RPC call

// A request to ping server and test its readiness for key operations.
type PingRequest struct {
	Password string // access is only granted after correct password is given
}

// If the server is ready to manage encryption keys, return nothing successfully. Return an error if otherwise.
func (rpcConn *CryptServiceConn) Ping(req PingRequest, _ *DummyAttr) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	}
	if err := rpcConn.Svc.CheckInitialSetup(); err != nil {
		return fmt.Errorf("Ping: the server is not ready to manage encryption keys - %v", err)
	}
	return nil
}

type DummyAttr bool // dummy type for a placeholder receiver in an RPC function

// A request to upload an encryption key to server.
type SaveKeyReq struct {
	Password string       // access is granted only after the correct password is given
	Hostname string       // client's host name (for logging only)
	Record   keydb.Record // the new key record
}

// Save a new key record.
func (rpcConn *CryptServiceConn) SaveKey(req SaveKeyReq, _ *DummyAttr) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	}
	// Input record may not contain empty attributes
	req.Record.FillBlanks()
	// The requester is considered to be the last host to have "retrieved" the key
	req.Record.LastRetrieval = keydb.AliveMessage{
		Hostname:  req.Hostname,
		IP:        rpcConn.RemoteAddr,
		Timestamp: time.Now().Unix(),
	}
	// Input record must be validated before saving
	if err := req.Record.Validate(); err != nil {
		return err
	}
	// TODO: insert KMIP logic here
	if _, err := rpcConn.Svc.KeyDB.Upsert(req.Record); err != nil {
		return err
	}
	// Format a record for journal
	journalRec := req.Record
	journalRec.Key = nil
	// Always log to system journal
	log.Printf(`SaveKey: %s (%s) has saved new key %s`,
		rpcConn.RemoteAddr, req.Hostname, journalRec.FormatAttrs(" "))
	// Send optional notification email in background
	if rpcConn.Svc.Mailer.ValidateConfig() == nil {
		go func() {
			// Put IP and mount point in subject and key record details in text
			subject := fmt.Sprintf("%s - %s (%s) %s", rpcConn.Svc.Config.KeyCreationSubject,
				rpcConn.RemoteAddr, req.Hostname, journalRec.MountPoint)
			text := fmt.Sprintf("%s\r\n\r\n%s", rpcConn.Svc.Config.KeyCreationGreeting, journalRec.FormatAttrs("\r\n"))
			if err := rpcConn.Svc.Mailer.Send(subject, text); err != nil {
				log.Printf("SaveKey: failed to send email notification after saving %s (%s)'s key of %s - %v",
					rpcConn.RemoteAddr, req.Hostname, req.Record.MountPoint, err)
			}
		}()
	}
	return nil
}

// Log key retrieval event to stderr and send optional notification emails.
func (rpcConn *CryptServiceConn) logRetrieval(uuids []string, hostname string, granted map[string]keydb.Record, rejected, missing []string) {
	// Always log to system journal
	retrievedUUIDs := make([]string, 0, len(uuids))
	for uuid := range granted {
		retrievedUUIDs = append(retrievedUUIDs, uuid)
	}
	if len(granted) > 0 {
		log.Printf(`RetrieveKey: %s (%s) has been granted keys of: %s`,
			rpcConn.RemoteAddr, hostname, strings.Join(retrievedUUIDs, " "))
	}
	if len(rejected) > 0 {
		log.Printf(`RetrieveKey: %s (%s) has been rejected keys of: %s`,
			rpcConn.RemoteAddr, hostname, strings.Join(rejected, " "))
	}
	// There is really no need to log the missing keys
	// Send optional notification email in background
	if rpcConn.Svc.Mailer.ValidateConfig() == nil && len(granted) > 0 {
		go func(granted map[string]keydb.Record) {
			// Put IP + host name in subject and UUID + mount point in text
			subject := fmt.Sprintf("%s - %s %s", rpcConn.Svc.Config.KeyRetrievalSubject, rpcConn.RemoteAddr, hostname)
			text := fmt.Sprintf("%s\r\n\r\n", rpcConn.Svc.Config.KeyRetrievalGreeting)
			for uuid, record := range granted {
				text += fmt.Sprintf("%s - %s\r\n", uuid, record.MountPoint)
			}
			if err := rpcConn.Svc.Mailer.Send(subject, text); err != nil {
				log.Printf("RetrieveKey: failed to send email notification after granting keys to %s (%s) - %v",
					rpcConn.RemoteAddr, hostname, err)
			}
		}(granted)
	}
}

// A request to retrieve encryption keys without using password.
type AutoRetrieveKeyReq struct {
	UUIDs    []string // (locked) file system UUIDs
	Hostname string   // client's host name (for logging only)
}

// A response to key retrieval (without using password) request.
type AutoRetrieveKeyResp struct {
	Granted  map[string]keydb.Record // these keys are now granted to the requester
	Rejected []string                // these keys exist in database but are not allowed to be retrieved at the moment
	Missing  []string                // these keys cannot be found in database
}

// Retrieve encryption keys without using a password. The request is usually sent automatically when disk comes online.
func (rpcConn *CryptServiceConn) AutoRetrieveKey(req AutoRetrieveKeyReq, resp *AutoRetrieveKeyResp) error {
	// Retrieve the keys and write down who retrieved it
	requester := keydb.AliveMessage{
		IP:        rpcConn.RemoteAddr,
		Hostname:  req.Hostname,
		Timestamp: time.Now().Unix(),
	}
	resp.Granted, resp.Rejected, resp.Missing = rpcConn.Svc.KeyDB.Select(requester, true, req.UUIDs...)
	rpcConn.logRetrieval(req.UUIDs, req.Hostname, resp.Granted, resp.Rejected, resp.Missing)
	return nil
}

// A request to forcibly retrieve encryption keys using a password.
type ManualRetrieveKeyReq struct {
	Password string   // access to keys is granted only after the correct password is given.
	UUIDs    []string // (locked) file system UUIDs
	Hostname string   // client's host name (for logging only)
}

// A response to forced key retrieval (with password) request.
type ManualRetrieveKeyResp struct {
	Granted map[string]keydb.Record // these keys are now granted to the requester
	Missing []string                // these keys cannot be found in database
}

// Retrieve encryption keys using a password. All requested keys will be granted regardless of MaxActive restriction.
func (rpcConn *CryptServiceConn) ManualRetrieveKey(req ManualRetrieveKeyReq, resp *ManualRetrieveKeyResp) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	}
	// Retrieve the keys and write down who retrieved it
	requester := keydb.AliveMessage{
		IP:        rpcConn.RemoteAddr,
		Hostname:  req.Hostname,
		Timestamp: time.Now().Unix(),
	}
	resp.Granted, _, resp.Missing = rpcConn.Svc.KeyDB.Select(requester, false, req.UUIDs...)
	rpcConn.logRetrieval(req.UUIDs, req.Hostname, resp.Granted, []string{}, resp.Missing)
	return nil
}

// A request to submit an alive report.
type ReportAliveReq struct {
	Hostname string   // client's host name (for logging only)
	UUIDs    []string // UUID of disks that are reportedly alive
}

/*
Submit a report that says the requester is still alive and holding the encryption keys. No password required.
Respond with UUID of keys that are rejected - which means they previously lost contact with the requester and no longer
consider it eligible to hold the keys.
*/
func (rpcConn *CryptServiceConn) ReportAlive(req ReportAliveReq, rejectedUUIDs *[]string) error {
	requester := keydb.AliveMessage{
		IP:        rpcConn.RemoteAddr,
		Hostname:  req.Hostname,
		Timestamp: time.Now().Unix(),
	}
	*rejectedUUIDs = rpcConn.Svc.KeyDB.UpdateAliveMessage(requester, req.UUIDs...)
	return nil
}

// A request to erase an encryption key.
type EraseKeyReq struct {
	Password string // access is granted only after the correct password is given
	Hostname string // client's host name (for logging only)
	UUID     string // UUID of the disk to delete key for
}

func (rpcConn *CryptServiceConn) EraseKey(req EraseKeyReq, _ *DummyAttr) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	}
	return rpcConn.Svc.KeyDB.Erase(req.UUID)
}

// Reload key database into memory. This function can only be called from 127.0.0.1. No password is required.
func (rpcConn *CryptServiceConn) ReloadDB(_ DummyAttr, _ *DummyAttr) error {
	if rpcConn.RemoteAddr != "127.0.0.1" {
		return errors.New("ReloadDB: remote IP is not 127.0.0.1")
	}
	return rpcConn.Svc.KeyDB.ReloadDB()
}

// A request to shut down the server so that it stops accepting connections.
type ShutdownReq struct {
	Challenge []byte
}

// Shut down the server's listener. This function can only be called from 127.0.0.1 with a correct secret challenge.
func (rpcConn *CryptServiceConn) Shutdown(req ShutdownReq, _ *DummyAttr) error {
	if rpcConn.RemoteAddr != "127.0.0.1" {
		return errors.New("Shutdown: remote IP is not 127.0.0.1")
	}
	if subtle.ConstantTimeCompare(rpcConn.Svc.ShutdownChallenge, req.Challenge) != 1 {
		return errors.New("Shutdown: incorrect pass")
	}
	err := rpcConn.Svc.Listener.Close()
	return err
}
