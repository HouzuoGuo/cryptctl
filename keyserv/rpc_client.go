// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"net"
	"net/rpc"
	"os"
	"path"
	"testing"
	"time"
)

const (
	RPC_DIAL_TIMEOUT_SEC = 10
	CLIENT_CONF_HOST     = "KEY_SERVER_HOST"
	CLIENT_CONF_PORT     = "KEY_SERVER_PORT"
	CLIENT_CONF_CA       = "TLS_CA_PEM"
	CLIENT_CONF_CERT     = "TLS_CERT_PEM"
	CLIENT_CONF_CERT_KEY = "TLS_CERT_KEY_PEM"
	TEST_RPC_PASS        = "pass"
)

type CryptClient struct {
	ServerHost string
	ServerPort int
	TLSCert    string
	TLSKey     string
	TLSConfig  *tls.Config
}

/*
Initialise an RPC client.
The function does not immediately establish a connection to server, connection is only made along with each RPC call.
*/
func NewCryptClient(host string, port int, caCertPEM []byte, certPath, certKeyPath string) (*CryptClient, error) {
	client := &CryptClient{
		ServerHost: host,
		ServerPort: port,
		TLSConfig:  new(tls.Config),
	}
	if caCertPEM != nil && len(caCertPEM) > 0 {
		// Use custom CA
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("NewCryptClient: failed to load custom CA certificates from PEM")
		}
		client.TLSConfig.RootCAs = caCertPool
	}
	if certPath != "" {
		// Tell client to present its identity to server
		clientCert, err := tls.LoadX509KeyPair(certPath, certKeyPath)
		if err != nil {
			return nil, err
		}
		client.TLSConfig.Certificates = []tls.Certificate{clientCert}
	}
	client.TLSConfig.BuildNameToCertificate()
	return client, nil
}

// Initialise an RPC client by reading settings from sysconfig file.
func NewCryptClientFromSysconfig(sysconf *sys.Sysconfig) (*CryptClient, error) {
	host := sysconf.GetString(CLIENT_CONF_HOST, "")
	if host == "" {
		return nil, errors.New("NewCryptClientFromSysconfig: key server host is empty")
	}
	port := sysconf.GetInt(CLIENT_CONF_PORT, 3737)
	if port == 0 {
		return nil, errors.New("NewCryptClientFromSysconfig: key server port number is empty")
	}
	var caCertPEM []byte
	if ca := sysconf.GetString(CLIENT_CONF_CA, ""); ca != "" {
		var err error
		caCertPEM, err = ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("NewCryptClientFromSysconfig: failed to read CA PEM file at \"%s\" - %v", ca, err)
		}
	}
	return NewCryptClient(host, port, caCertPEM, sysconf.GetString(CLIENT_CONF_CERT, ""), sysconf.GetString(CLIENT_CONF_CERT_KEY, ""))
}

/*
Establish a new TLS connection to RPC server and then invoke an RPC on the connection.
The function deliberately establishes a new connection on each RPC call, in order to reduce complexity in managing
the client connections, especially in the area of keep-alive. The client is not expected to make high volume of calls
hence there is absolutely no performance concern.
*/
func (client *CryptClient) DoRPC(fun func(*rpc.Client) error) error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: RPC_DIAL_TIMEOUT_SEC * time.Second},
		"tcp", fmt.Sprintf("%s:%d", client.ServerHost, client.ServerPort),
		client.TLSConfig)
	if err != nil {
		return fmt.Errorf("DoRPC: failed to connect to %s on port %d - %v", client.ServerHost, client.ServerPort, err)
	}
	defer conn.Close()
	rpcClient := rpc.NewClient(conn)
	defer rpcClient.Close()
	if err := fun(rpcClient); err != nil {
		return fmt.Errorf("DoRPC: call failed - %v", err)
	}
	return nil
}

// Retrieve the salt that was used to hash server's access password.
func (client *CryptClient) GetSalt() (salt PasswordSalt, err error) {
	err = client.DoRPC(func(rpcClient *rpc.Client) error {
		var dummy DummyAttr
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "GetSalt"), &dummy, &salt)
	})
	return
}

// Ping RPC server. Return an error if there is a communication mishap or server has not undergone the initial setup.
func (client *CryptClient) Ping(req PingRequest) error {
	return client.DoRPC(func(rpcClient *rpc.Client) error {
		var dummy DummyAttr
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "Ping"), req, &dummy)
	})
}

// Create a new key record.
func (client *CryptClient) CreateKey(req CreateKeyReq) (resp CreateKeyResp, err error) {
	err = client.DoRPC(func(rpcClient *rpc.Client) error {
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "CreateKey"), req, &resp)
	})
	return
}

// Retrieve encryption keys without a password.
func (client *CryptClient) AutoRetrieveKey(req AutoRetrieveKeyReq) (resp AutoRetrieveKeyResp, err error) {
	err = client.DoRPC(func(rpcClient *rpc.Client) error {
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "AutoRetrieveKey"), req, &resp)
	})
	return
}

// Retrieve encryption keys using a password. All requested keys will be granted regardless of MaxActive restriction.
func (client *CryptClient) ManualRetrieveKey(req ManualRetrieveKeyReq) (resp ManualRetrieveKeyResp, err error) {
	err = client.DoRPC(func(rpcClient *rpc.Client) error {
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "ManualRetrieveKey"), req, &resp)
	})
	return
}

/*
Submit a report that says the requester is still alive and holding the encryption keys. Return UUID of keys that are
rejected - which means they previously lost contact with this host and no longer consider it eligible to hold the keys.
*/
func (client *CryptClient) ReportAlive(req ReportAliveReq) (rejectedUUIDs []string, err error) {
	err = client.DoRPC(func(rpcClient *rpc.Client) error {
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "ReportAlive"), req, &rejectedUUIDs)
	})
	return
}

// Tell server to delete an encryption key.
func (client *CryptClient) EraseKey(req EraseKeyReq) error {
	return client.DoRPC(func(rpcClient *rpc.Client) error {
		var dummy DummyAttr
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "EraseKey"), req, &dummy)
	})
}

// Shut down server's listener.
func (client *CryptClient) Shutdown(req ShutdownReq) error {
	return client.DoRPC(func(rpcClient *rpc.Client) error {
		var dummy DummyAttr
		return rpcClient.Call(fmt.Sprintf(RPCObjNameFmt, "Shutdown"), req, &dummy)
	})
}

// Start an RPC server in a testing configuration, return a client connected to the server and a teardown function.
func StartTestServer(tb testing.TB) (*CryptClient, func(testing.TB)) {
	keydbDir, err := ioutil.TempDir("", "cryptctl-rpctest")
	if err != nil {
		tb.Fatal(err)
		return nil, nil
	}
	// Fill in configuration blanks (listen port is left at default)
	salt := NewSalt()
	passHash := HashPassword(salt, TEST_RPC_PASS)
	sysconf := GetDefaultKeySvcConf()
	sysconf.Set(SRV_CONF_KEYDB_DIR, keydbDir)
	sysconf.Set(SRV_CONF_TLS_CERT, path.Join(PkgInGopath, "keyserv", "rpc_test.crt"))
	sysconf.Set(SRV_CONF_TLS_KEY, path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
	sysconf.Set(SRV_CONF_PASS_SALT, hex.EncodeToString(salt[:]))
	sysconf.Set(SRV_CONF_PASS_HASH, hex.EncodeToString(passHash[:]))
	// Start server
	srvConf := CryptServiceConfig{}
	srvConf.ReadFromSysconfig(sysconf)
	srv, err := NewCryptServer(srvConf, Mailer{})
	if err != nil {
		tb.Fatal(err)
		return nil, nil
	}
	if err := srv.ListenRPC(); err != nil {
		tb.Fatal(err)
		return nil, nil
	}
	go srv.HandleConnections()
	// The test certificate's CN is "localhost"
	caPath := path.Join(PkgInGopath, "keyrpc", "rpc_test.crt")
	certContent, err := ioutil.ReadFile(caPath)
	// Construct a client via function parameters
	client, err := NewCryptClient("localhost", 3737, certContent, "", "")
	if err != nil {
		tb.Fatal(err)
		return nil, nil
	}
	client.TLSConfig.InsecureSkipVerify = true
	// Server should start within about 2 seconds
	serverReady := false
	for i := 0; i < 20; i++ {
		if err := client.Ping(PingRequest{Password: HashPassword(salt, TEST_RPC_PASS)}); err == nil {
			serverReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !serverReady {
		tb.Fatal("server did not start in time")
		return nil, nil
	}
	tearDown := func(t testing.TB) {
		if err := client.Shutdown(ShutdownReq{Challenge: srv.AdminChallenge}); err != nil {
			t.Fatal(err)
			return
		}
		if err := client.Ping(PingRequest{Password: HashPassword(salt, TEST_RPC_PASS)}); err == nil {
			t.Fatal("server did not shutdown")
			return
		}
		if err := os.RemoveAll(keydbDir); err != nil {
			t.Fatal(err)
			return
		}
	}
	return client, tearDown
}
