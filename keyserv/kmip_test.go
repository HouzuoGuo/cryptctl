package keyserv

import (
	"github.com/HouzuoGuo/cryptctl/keydb"
	"io/ioutil"
	"os"
	"path"
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
	go func() {
		var err error
		server, err = NewKMIPServer(db, path.Join(PkgInGopath, "keyserv", "rpc_test.crt"), path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Listen(); err != nil {
			t.Fatal(err)
		}
	}()
	// Expect server to start in a second
	time.Sleep(1 * time.Second)
	client, err := NewKMIPClient("127.0.0.1", server.GetPort(), "", string(server.PasswordChallenge), nil,
		path.Join(PkgInGopath, "keyserv", "rpc_test.crt"), path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
	// In case the test certificate name does not match 127.0.0.1
	client.TLSConfig.InsecureSkipVerify = true
	if err != nil {
		t.Fatal(err)
	}
	if id, err := client.CreateKey("testname"); err != nil || id != "1" {
		t.Fatal(err, id)
	}
}
