// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"crypto/sha512"
	"encoding/hex"
	"path"
	"reflect"
	"testing"
)

func TestHashPassword(t *testing.T) {
	salt := [sha512.Size]byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
	hash := HashPassword(salt, "pass")

	/*
		The hash result is verified by openssl:

		together := make([]byte, sha512.Size + 4)
		copy(together, salt[:])
		copy(together[sha512.Size:], []byte("pass"))
		_, out, _, err := sys.Exec(bytes.NewReader(together), nil, nil, "openssl", "sha512", "-binary")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println([]byte(out))
	*/

	if hash != [sha512.Size]byte{
		190, 95, 250, 155, 21, 243, 233, 118,
		22, 89, 166, 222, 173, 141, 32, 238,
		90, 23, 90, 45, 118, 146, 138, 167,
		41, 193, 77, 223, 139, 238, 192, 82,
		15, 208, 110, 7, 67, 139, 254, 210,
		182, 211, 16, 39, 244, 118, 68, 104,
		228, 23, 175, 140, 112, 149, 59, 116,
		58, 90, 141, 114, 104, 209, 219, 36,
	} {
		t.Fatal(hash)
	}
}

func TestNewSalt(t *testing.T) {
	salt := NewSalt()
	all0 := true
	for _, b := range salt {
		if b != 0 {
			all0 = false
		}
	}
	if all0 {
		t.Fatal(salt)
	}
	salt2 := NewSalt()
	if reflect.DeepEqual(salt, salt2) {
		t.Fatal("not random")
	}
}

func TestServiceReadFromSysconfig(t *testing.T) {
	sysconf := GetDefaultKeySvcConf()
	svcConf := CryptServiceConfig{}
	if err := svcConf.ReadFromSysconfig(sysconf); err == nil {
		t.Fatal("did not error")
	}
	// Fill in blanks in the default configuration and load once more
	hash := HashPassword(NewSalt(), "")
	sysconf.Set(SRV_CONF_PASS_HASH, hex.EncodeToString(hash[:]))
	salt := NewSalt()
	sysconf.Set(SRV_CONF_PASS_SALT, hex.EncodeToString(salt[:]))
	sysconf.Set(SRV_CONF_TLS_CERT, "/etc/os-release")
	sysconf.Set(SRV_CONF_TLS_KEY, "/etc/os-release")
	sysconf.Set(SRV_CONF_LISTEN_ADDR, "1.1.1.1")
	sysconf.Set(SRV_CONF_LISTEN_PORT, "1234")
	sysconf.Set(SRV_CONF_KEYDB_DIR, "/abc")
	sysconf.Set(SRV_CONF_MAIL_CREATION_SUBJ, "a")
	sysconf.Set(SRV_CONF_MAIL_CREATION_TEXT, "b")
	sysconf.Set(SRV_CONF_MAIL_RETRIEVAL_SUBJ, "c")
	sysconf.Set(SRV_CONF_MAIL_RETRIEVAL_TEXT, "d")
	if err := svcConf.ReadFromSysconfig(sysconf); err == nil {
		t.Fatal("did not error on bad tls")
	}
	sysconf.Set("TLS_CERT_PEM", path.Join(PkgInGopath, "keyserv", "rpc_test.crt"))
	sysconf.Set("TLS_CERT_KEY_PEM", path.Join(PkgInGopath, "keyserv", "rpc_test.key"))
	if err := svcConf.ReadFromSysconfig(sysconf); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(svcConf, CryptServiceConfig{
		PasswordHash:         hash,
		PasswordSalt:         salt,
		CertPEM:              path.Join(PkgInGopath, "keyserv", "rpc_test.crt"),
		KeyPEM:               path.Join(PkgInGopath, "keyserv", "rpc_test.key"),
		Address:              "1.1.1.1",
		Port:                 1234,
		KeyDBDir:             "/abc",
		KeyCreationSubject:   "a",
		KeyCreationGreeting:  "b",
		KeyRetrievalSubject:  "c",
		KeyRetrievalGreeting: "d",
		KMIPAddresses:        []string{},
	}) {
		t.Fatalf("%+v", svcConf)
	}
}

// RPC functions are tested by CryptClient test cases.
