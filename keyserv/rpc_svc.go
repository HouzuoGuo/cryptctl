// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/fs"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"log"
	"net"
	"net/rpc"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	LenAdminChallenge = 64   // length of the random challenge that must be verified in order to shutdown server
	LEN_PASS_SALT     = 64   // length of random salt to go with each password
	SRV_DEFAULT_PORT  = 3737 // default port for the key server to listen on

	SRV_CONF_PASS_HASH           = "AUTH_PASSWORD_HASH"
	SRV_CONF_PASS_SALT           = "AUTH_PASSWORD_SALT"
	SRV_CONF_TLS_CA              = "TLS_CA_PEM"
	SRV_CONF_TLS_CERT            = "TLS_CERT_PEM"
	SRV_CONF_TLS_KEY             = "TLS_CERT_KEY_PEM"
	SRV_CONF_TLS_VALIDATE_CLIENT = "TLS_VALIDATE_CLIENT"
	SRV_CONF_LISTEN_ADDR         = "LISTEN_ADDRESS"
	SRV_CONF_LISTEN_PORT         = "LISTEN_PORT"
	SRV_CONF_KEYDB_DIR           = "KEY_DB_DIR"
	SRV_CONF_MAIL_CREATION_SUBJ  = "EMAIL_KEY_CREATION_SUBJECT"
	SRV_CONF_MAIL_CREATION_TEXT  = "EMAIL_KEY_CREATION_GREETING"
	SRV_CONF_MAIL_RETRIEVAL_SUBJ = "EMAIL_KEY_RETRIEVAL_SUBJECT"
	SRV_CONF_MAIL_RETRIEVAL_TEXT = "EMAIL_KEY_RETRIEVAL_GREETING"

	SRV_CONF_KMIP_SERVER_ADDRS    = "KMIP_SERVER_ADDRESSES"
	SRV_CONF_KMIP_SERVER_USER     = "KMIP_SERVER_USER"
	SRV_CONF_KMIP_SERVER_PASS     = "KMIP_SERVER_PASS"
	SRV_CONF_KMIP_TLS_DO_VERIFY   = "KMIP_TLS_DO_VERIFY"
	SRV_CONF_KMIP_SERVER_TLS_CA   = "KMIP_CA_PEM"
	SRV_CONF_KMIP_SERVER_TLS_CERT = "KMIP_TLS_CERT_PEM"
	SRV_CONF_KMIP_SERVER_TLS_KEY  = "KMIP_TLS_CERT_KEY_PEM"

	KeyNamePrefix = "cryptctl-" // Prefix string prepended to KMIP keys
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
func NewSalt() (ret PasswordSalt) {
	if _, err := rand.Read(ret[:]); err != nil {
		panic(fmt.Errorf("NewSalt: failed to read from random source - %v", err))
	}
	return
}

type PasswordSalt [LEN_PASS_SALT]byte
type HashedPassword [sha512.Size]byte

// Compute a salted password hash using SHA512 method.
func HashPassword(salt PasswordSalt, plainText string) HashedPassword {
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
	CertAuthorityPEM     string              // path to PEM-encoded CA certificate
	ValidateClientCert   bool                // whether the server will authenticate its client before accepting RPC request
	CertPEM              string              // path to PEM-encoded TLS certificate
	KeyPEM               string              // path to PEM-encoded TLS certificate key
	Address              string              // address of the network interface to listen on
	Port                 int                 // port to listen on
	KeyDBDir             string              // key database directory
	KeyCreationSubject   string              // subject of the notification email sent by key creation request
	KeyCreationGreeting  string              // greeting of the notification email sent by key creation request
	KeyRetrievalSubject  string              // subject of the notification email sent by key retrieval request
	KeyRetrievalGreeting string              // greeting of the notification email sent by key retrieval request
	KMIPAddresses        []string            // optional KMIP server addresses (server1:port1 server2:port2 ...)
	KMIPUser             string              // optional KMIP service access user
	KMIPPass             string              // optional KMIP service access password
	KMIPCertAuthorityPEM string              // optional KMIP server CA certificate
	KMIPTLSDoVerify      bool                // Enable verification on KMIP server's TLS certificate
	KMIPCertPEM          string              // optional KMIP client certificate
	KMIPKeyPEM           string              // optional KMIP client certificate key
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

	conf.CertAuthorityPEM = sysconf.GetString(SRV_CONF_TLS_CA, "")
	conf.ValidateClientCert = sysconf.GetBool(SRV_CONF_TLS_VALIDATE_CLIENT, false)
	conf.CertPEM = sysconf.GetString(SRV_CONF_TLS_CERT, "")
	conf.KeyPEM = sysconf.GetString(SRV_CONF_TLS_KEY, "")
	conf.Address = sysconf.GetString(SRV_CONF_LISTEN_ADDR, "0.0.0.0")
	conf.Port = sysconf.GetInt(SRV_CONF_LISTEN_PORT, SRV_DEFAULT_PORT)

	conf.KeyDBDir = sysconf.GetString(SRV_CONF_KEYDB_DIR, "/var/lib/cryptctl/keydb")

	conf.KeyCreationSubject = sysconf.GetString(SRV_CONF_MAIL_CREATION_SUBJ, "A new file system has been encrypted")
	conf.KeyCreationGreeting = sysconf.GetString(SRV_CONF_MAIL_CREATION_TEXT, "The key server now has encryption key for the following file system:")
	conf.KeyRetrievalSubject = sysconf.GetString(SRV_CONF_MAIL_RETRIEVAL_SUBJ, "An encrypted file system has been accessed")
	conf.KeyRetrievalGreeting = sysconf.GetString(SRV_CONF_MAIL_RETRIEVAL_TEXT, "The key server has sent the following encryption key to allow access to its file systems:")

	conf.KMIPAddresses = sysconf.GetStringArray(SRV_CONF_KMIP_SERVER_ADDRS, []string{})
	conf.KMIPUser = sysconf.GetString(SRV_CONF_KMIP_SERVER_USER, "")
	conf.KMIPPass = sysconf.GetString(SRV_CONF_KMIP_SERVER_PASS, "")
	conf.KMIPCertAuthorityPEM = sysconf.GetString(SRV_CONF_KMIP_SERVER_TLS_CA, "")
	conf.KMIPTLSDoVerify = sysconf.GetBool(SRV_CONF_KMIP_TLS_DO_VERIFY, true)
	conf.KMIPCertPEM = sysconf.GetString(SRV_CONF_KMIP_SERVER_TLS_CERT, "")
	conf.KMIPKeyPEM = sysconf.GetString(SRV_CONF_KMIP_SERVER_TLS_KEY, "")
	return conf.Validate()
}

// RPC and KMIP server for accessing encryption keys.
type CryptServer struct {
	Config            CryptServiceConfig // service configuration
	Mailer            *Mailer            // mail notification sender
	KeyDB             *keydb.DB          // encryption key database
	TLSConfig         *tls.Config        // TLS certificate chain and private key
	Listener          net.Listener       // listener for client connections
	BuiltInKMIPServer *KMIPServer        // Built-in KMIP server in case there's no external server
	KMIPClient        *KMIPClient        // KMIP client connected to either built-in KMIP server or external server
	AdminChallenge    []byte             // a random secret that must be verified for incoming shutdown/reload requests
}

// Initialise an RPC server from sysconfig file text.
func NewCryptServer(config CryptServiceConfig, mailer Mailer) (srv *CryptServer, err error) {
	if err = config.Validate(); err != nil {
		return nil, err
	}
	srv = &CryptServer{
		Config:    config,
		Mailer:    &mailer,
		TLSConfig: new(tls.Config),
	}
	srv.KeyDB, err = keydb.OpenDB(config.KeyDBDir)
	if err != nil {
		return nil, err
	}
	/*
	 The author of TLS related libraries in Go has an opinion about CRL
	*/
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(config.CertPEM, config.KeyPEM)
	// Configure client authentication upon request
	if config.ValidateClientCert {
		caPEM, err := ioutil.ReadFile(config.CertAuthorityPEM)
		if err != nil {
			return nil, err
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caPEM)
		srv.TLSConfig.ClientCAs = caPool
		srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	srv.TLSConfig.BuildNameToCertificate()
	// Admin challenge is an array of random bytes
	srv.AdminChallenge = make([]byte, LenAdminChallenge)
	if _, err = rand.Read(srv.AdminChallenge); err != nil {
		return
	}
	return
}

/*
Start RPC server. If the RPC server does not have KMIP connectivity settings, start an incomplete implementation
of KMIP server.
Block caller until the listener quits.
*/
func (srv *CryptServer) ListenRPC() error {
	var err error
	if len(srv.Config.KMIPAddresses) == 0 {
		// If RPC server settings do not have KMIP connectivity settings, start my own KMIP server.
		if srv.BuiltInKMIPServer, err = NewKMIPServer(srv.KeyDB, srv.Config.CertPEM, srv.Config.KeyPEM); err != nil {
			return err
		}
		if err := srv.BuiltInKMIPServer.Listen(); err != nil {
			return err
		}
		go srv.BuiltInKMIPServer.HandleConnections()
		// The client initialisation routine does not immediately connect to server.
		if srv.KMIPClient, err = NewKMIPClient(
			[]string{"localhost:" + strconv.Itoa(srv.BuiltInKMIPServer.GetPort())},
			"does-not-matter", string(srv.BuiltInKMIPServer.PasswordChallenge),
			nil, "", ""); err != nil {
			return err
		}
		srv.KMIPClient.TLSConfig.InsecureSkipVerify = true
	} else {
		// No need to start built-in KMIP server, so only initialise the client.
		var caCert []byte
		if srv.Config.KMIPCertAuthorityPEM != "" {
			caCert, err = ioutil.ReadFile(srv.Config.KMIPCertAuthorityPEM)
			if err != nil {
				return err
			}
		}
		if srv.KMIPClient, err = NewKMIPClient(
			srv.Config.KMIPAddresses,
			srv.Config.KMIPUser, srv.Config.KMIPPass,
			caCert, srv.Config.KMIPCertPEM, srv.Config.KMIPKeyPEM); err != nil {
			return err
		}
		if !srv.Config.KMIPTLSDoVerify {
			log.Printf("CryptServer.ListenRPC: KMIP client will not verify KMIP server's identity, as instructed by configuration.")
			srv.KMIPClient.TLSConfig.InsecureSkipVerify = !srv.Config.KMIPTLSDoVerify
		}
	}
	// Start ordinary RPC server
	if srv.Listener, err = tls.Listen("tcp", fmt.Sprintf("%s:%d", srv.Config.Address, srv.Config.Port), srv.TLSConfig); err != nil {
		return fmt.Errorf("CryptServer.ListenRPC: failed to listen on %s:%d - %v", srv.Config.Address, srv.Config.Port, err)
	}
	log.Printf("CryptServer.ListenRPC: listening on %s:%d using TLS certficate \"%s\"", srv.Config.Address, srv.Config.Port, srv.Config.CertPEM)
	return nil
}

// Handle incoming connections in a loop. Block caller until listener closes.
func (srv *CryptServer) HandleConnections() {
	for {
		incoming, err := srv.Listener.Accept()
		if err != nil {
			log.Printf("CryptServer.HandleConnections: quit now - %v", err)
			return
		}
		// The connection is served by a dedicated RPC server instance
		go func(conn net.Conn) {
			srv.ServeConn(conn)
			conn.Close()
		}(incoming)
	}
}

// Shut down RPC server listener. If built-in KMIP server was started, shut that one down as well.
func (srv *CryptServer) Shutdown() {
	if listener := srv.Listener.Close(); listener != nil {
		srv.Listener.Close()
	}
	if kmipServer := srv.BuiltInKMIPServer; kmipServer != nil {
		kmipServer.Shutdown()
	}
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
func (srv *CryptServer) ValidatePassword(pass HashedPassword) error {
	// Fail straight away if server setup is missing
	if err := srv.CheckInitialSetup(); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(pass[:], srv.Config.PasswordHash[:]) != 1 {
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
	Password HashedPassword // access is only granted after correct password is given
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

// A request to create an encryption key on server.
type CreateKeyReq struct {
	Password         HashedPassword // access is granted only after the correct password is given
	Hostname         string         // computer host name (for logging only)
	UUID             string         // file system uuid
	MountPoint       string         // mount point of the file system
	MountOptions     []string       // mount options of the file system
	MaxActive        int            // maximum allowed active key users (computers), set to <=0 to allow unlimited.
	AliveIntervalSec int            //interval in seconds at which all user of the file system holding this key must report they're online
	AliveCount       int            //a computer holding the file system is considered offline after missing so many alive messages
}

// Make sure that the request attributes are sane.
func (req CreateKeyReq) Validate() error {
	if req.UUID == "" {
		return errors.New("UUID must not be empty")
	} else if cleanedID := filepath.Clean(req.UUID); cleanedID != req.UUID {
		return errors.New("Illegal characters appeared in UUID")
	} else if req.MountPoint == "" {
		return errors.New("Mount point must not be empty")
	}
	return nil
}

// A response to a newly saved key
type CreateKeyResp struct {
	KeyContent []byte // Disk encryption key
}

// Save a new key record.
func (rpcConn *CryptServiceConn) CreateKey(req CreateKeyReq, resp *CreateKeyResp) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	} else if err := req.Validate(); err != nil {
		return err
	}
	/*
		No matter key is located in built-in KMIP server or external KMIP server, the KMIP client needs to create the key.
		But if the KMIP server is an external appliance, having the name prefix makes it more apparent where the key
		originates.
		If KMIP server is the built-in one, the server will remove the prefix string before storing record UUID in built-in key database.
		But key database only recognises UUID, there's no need for a prefix to be stored in key database.
	*/
	kmipKeyID, err := rpcConn.Svc.KMIPClient.CreateKey(KeyNamePrefix + req.UUID)
	if err != nil {
		return fmt.Errorf("CryptServiceConn.CreateKey: KMIP client refused to create the key - %v", err)
	}
	// Complete key tracking record in my database
	var keyRecord keydb.Record
	if rpcConn.Svc.BuiltInKMIPServer != nil {
		// Retrieve the incomplete key record saved by built-in KMIP server
		var found bool
		keyRecord, found = rpcConn.Svc.KeyDB.GetByID(kmipKeyID)
		if !found {
			return fmt.Errorf("CryptServiceConn.CreateKey: new key ID \"%s\" just disappeared from database", kmipKeyID)
		}
	}
	/*
		If the record was created by built-in KMIP server, some record details are already in-place.
		But if external KMIP server was used, then the key record does not yet even exist in my database, hence complete all
		record details no matter what.
	*/
	keyRecord.ID = kmipKeyID
	keyRecord.Version = keydb.CurrentRecordVersion
	keyRecord.CreationTime = time.Now()
	keyRecord.UUID = req.UUID
	keyRecord.MountPoint = req.MountPoint
	keyRecord.MountOptions = req.MountOptions
	keyRecord.MaxActive = req.MaxActive
	keyRecord.AliveIntervalSec = req.AliveIntervalSec
	keyRecord.AliveCount = req.AliveCount
	if _, err := rpcConn.Svc.KeyDB.Upsert(keyRecord); err != nil {
		return fmt.Errorf("CryptServiceConn.CreateKey: failed to save key tracking record into database - %v", err)
	}
	// Ask server for the actual encryption key to formulate RPC response
	resp.KeyContent, err = rpcConn.askForKeyContent(kmipKeyID)
	if err != nil {
		return err
	}
	// Format a record for journal
	journalRec := keyRecord
	journalRec.Key = nil
	// Always log the event to system journal
	log.Printf(`CryptServiceConn.CreateKey: %s (%s) has saved new key %s`,
		rpcConn.RemoteAddr, req.Hostname, journalRec.FormatAttrs(" "))
	// Send optional notification email in background
	if rpcConn.Svc.Mailer.ValidateConfig() == nil {
		go func() {
			// Put IP and mount point in subject and key record details in text
			subject := fmt.Sprintf("%s - %s (%s) %s", rpcConn.Svc.Config.KeyCreationSubject,
				rpcConn.RemoteAddr, req.Hostname, journalRec.MountPoint)
			text := fmt.Sprintf("%s\r\n\r\n%s", rpcConn.Svc.Config.KeyCreationGreeting, journalRec.FormatAttrs("\r\n"))
			if err := rpcConn.Svc.Mailer.Send(subject, text); err != nil {
				log.Printf("CryptServiceConn.CreateKey: failed to send email notification after saving %s (%s)'s key of %s - %v",
					rpcConn.RemoteAddr, req.Hostname, journalRec.MountPoint, err)
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
		log.Printf(`CryptServiceConn.logRetrieval: %s (%s) has been granted keys of: %s`,
			rpcConn.RemoteAddr, hostname, strings.Join(retrievedUUIDs, " "))
	}
	if len(rejected) > 0 {
		log.Printf(`CryptServiceConn.logRetrieval: %s (%s) has been rejected keys of: %s`,
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
				log.Printf("CryptServiceConn.logRetrieval: failed to send email notification after granting keys to %s (%s) - %v",
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

// Retrieve key content by KMIP record ID. Return key content.
func (rpcConn *CryptServiceConn) askForKeyContent(kmipID string) (key []byte, err error) {
	key, err = rpcConn.Svc.KMIPClient.GetKey(kmipID)
	if err != nil {
		// This is severe enough to deserve a server side log message
		msg := fmt.Sprintf("CryptServiceConn.askForKeyContent: KMIP client failed to answer to key request - %v", err)
		log.Print(msg)
		return nil, errors.New(msg)
	}
	return
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
	// Key content of granted records are stored in KMIP
	for uuid, grantedRecord := range resp.Granted {
		key, err := rpcConn.askForKeyContent(grantedRecord.ID)
		if err != nil {
			return err
		}
		grantedRecord.Key = key
		resp.Granted[uuid] = grantedRecord
	}
	rpcConn.logRetrieval(req.UUIDs, req.Hostname, resp.Granted, resp.Rejected, resp.Missing)
	return nil
}

// A request to forcibly retrieve encryption keys using a password.
type ManualRetrieveKeyReq struct {
	Password HashedPassword // access to keys is granted only after the correct password is given.
	UUIDs    []string       // (locked) file system UUIDs
	Hostname string         // client's host name (for logging only)
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
	// Key content of granted records are stored in KMIP
	for uuid, grantedRecord := range resp.Granted {
		key, err := rpcConn.askForKeyContent(grantedRecord.ID)
		if err != nil {
			return err
		}
		grantedRecord.Key = key
		resp.Granted[uuid] = grantedRecord
	}
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
	Password HashedPassword // access is granted only after the correct password is given
	Hostname string         // client's host name (for logging only)
	UUID     string         // UUID of the disk to delete key for
}

func (rpcConn *CryptServiceConn) EraseKey(req EraseKeyReq, _ *DummyAttr) error {
	if err := rpcConn.Svc.ValidatePassword(req.Password); err != nil {
		return err
	}
	rec, found := rpcConn.Svc.KeyDB.GetByUUID(req.UUID)
	if !found {
		// No need to return error in case key has already disappeared from key server
		return nil
	}
	kmipErr := rpcConn.Svc.KMIPClient.DestroyKey(rec.ID)
	dbErr := rpcConn.Svc.KeyDB.Erase(req.UUID)
	if dbErr == nil && kmipErr != nil {
		return fmt.Errorf("EraseKey: key tracking record has been erased from database, but KMIP did not erase it - %v", kmipErr)
	}
	return dbErr
}

// A request to shut down the server so that it stops accepting connections.
type ShutdownReq struct {
	Challenge []byte
}

// Shut down the server's listener.
func (rpcConn *CryptServiceConn) Shutdown(req ShutdownReq, _ *DummyAttr) error {
	if subtle.ConstantTimeCompare(rpcConn.Svc.AdminChallenge, req.Challenge) != 1 {
		return errors.New("Shutdown: incorrect challenge")
	}
	err := rpcConn.Svc.Listener.Close()
	return err
}

// Hand over the salt that was used to hash server's access password.
func (rpcConn *CryptServiceConn) GetSalt(_ DummyAttr, salt *PasswordSalt) error {
	copy((*salt)[:], rpcConn.Svc.Config.PasswordSalt[:])
	return nil
}
