// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

func TestGenerateSelfSignedCertificate(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	if err := GenerateSelfSignedCertificate("example.com", path.Join(tmpDir, "cert"), path.Join(tmpDir, "key")); err != nil {
		t.Fatal(err)
	}
	cert, err := ioutil.ReadFile(path.Join(tmpDir, "cert"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Fatal(string(cert))
	}
	key, err := ioutil.ReadFile(path.Join(tmpDir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(key), "BEGIN PRIVATE KEY") {
		t.Fatal(string(key))
	}
	// The function must not overwrite existing files
	if err := GenerateSelfSignedCertificate("example.com", path.Join(tmpDir, "cert"), path.Join(tmpDir, "key")); err == nil {
		t.Fatal("did not error")
	}
	// Empty common name is an error condition
	if err := GenerateSelfSignedCertificate("", path.Join(tmpDir, "1"), path.Join(tmpDir, "2")); err == nil {
		t.Fatal("did not error")
	}
}
