package keyserv

import (
	"encoding/hex"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
	"time"
)

func TestKMIP(t *testing.T) {
	keydbDir, err := ioutil.TempDir("", "cryptctl-kmip-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(keydbDir)
	db, err := keydb.OpenDB(keydbDir)
	if err != nil {
		t.Fatal(err)
	}

	var server *KMIPServer
	var serverHasShutdown bool
	server, err = NewKMIPServer(db, path.Join(PkgInGopath, "keyserv", "rpc_test.crt"), path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
	if err != nil {
		t.Fatal(err)
	}
	if server.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() {
		server.HandleConnections()
		serverHasShutdown = true
	}()
	caCert, err := ioutil.ReadFile(path.Join(PkgInGopath, "keyserv", "rpc_test.crt"))
	if err != nil {
		t.Fatal(err)
	}
	// Expect server to start in a second
	time.Sleep(1 * time.Second)
	client, err := NewKMIPClient("localhost", server.GetPort(), "username-does-not-matter", string(server.PasswordChallenge), caCert,
		path.Join(PkgInGopath, "keyserv", "rpc_test.crt"), path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Create two keys
	if id, err := client.CreateKey("test key 1"); err != nil || id != "1" {
		t.Fatal(err, id)
	}
	if id, err := client.CreateKey("test key 2"); err != nil || id != "2" {
		t.Fatal(err, id)
	}
	// Retrieve both keys and non-existent key
	received1, err := client.GetKey("1")
	if err != nil {
		t.Fatal(err)
	}
	received2, err := client.GetKey("2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetKey("does not exist"); err == nil {
		t.Fatal("did not error")
	}
	if reflect.DeepEqual(received1, received2) || len(received1) == 0 {
		t.Fatal(hex.Dump(received1), hex.Dump(received2))
	}
	// Destroy and retrieve again
	if err := client.DestroyKey("1"); err != nil {
		t.Fatal(err)
	}
	if err := client.DestroyKey("does not exist"); err == nil {
		t.Fatal("did not error")
	}
	// Expect server to shut down within a second
	server.Shutdown()
	time.Sleep(1 * time.Second)
	if !serverHasShutdown {
		t.Fatal("did not shutdown")
	}
	// Calling shutdown multiple times should not cause panic
	server.Shutdown()
	server.Shutdown()
}

func TestKMIPAgainstPyKMIP(t *testing.T) {
	/*
			A PyKMIP server can be started using the python code below:
		import time
		from kmip.services.server import *

		server = KmipServer(
		    hostname='0.0.0.0',
		    port=5696,
		    certificate_path='/etc/pykmip/server.crt',
		    key_path='/etc/pykmip/server.key',
		    ca_path='/etc/pykmip/ca.crt',
		    auth_suite='Basic',
		    config_path=None,
		    log_path='/etc/pykmip/server.log',
		    policy_path='/etc/pykmip/policy.json'
		)

		print("server about to start")
		server.start()
		print("server started")
		server.serve()
		print("connection served")
		time.sleep(100)
	*/
	t.Skip("Start PyKMIP server manually and remove this skip statement to run this test case")
	client, err := NewKMIPClient("127.0.0.1", 5696, "testuser", "testpass", nil, "/etc/pykmip/client.crt", "/etc/pykmip/client.key")
	client.TLSConfig.InsecureSkipVerify = true
	if err != nil {
		t.Fatal(err)
	}
	// Create two keys
	var id1, id2 string
	if id1, err = client.CreateKey("test key 1"); err != nil || id1 == "" {
		t.Fatal(err, id1)
	}
	if id2, err = client.CreateKey("test key 2"); err != nil || id2 == "" {
		t.Fatal(err, id2)
	}
	// Retrieve both keys and non-existent key
	received1, err := client.GetKey(id1)
	if err != nil {
		t.Fatal(err)
	}
	received2, err := client.GetKey(id2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetKey("does not exist"); err == nil {
		t.Fatal("did not error")
	}
	if reflect.DeepEqual(received1, received2) || len(received1) == 0 {
		t.Fatal(hex.Dump(received1), hex.Dump(received2))
	}
	// Destroy and retrieve again
	if err := client.DestroyKey(id1); err != nil {
		t.Fatal(err)
	}
	if err := client.DestroyKey("does not exist"); err == nil {
		t.Fatal("did not error")
	}
}
