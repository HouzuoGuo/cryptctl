// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"fmt"
	"github.com/HouzuoGuo/cryptctl/sys"
	"io/ioutil"
	"os"
	"path"
)

const (
	BIN_OPENSSL = "/usr/bin/openssl"
)

// Invoke openssl command to make a self-signed certificate for this host.
func GenerateSelfSignedCertificate(commonName, certFilePath, keyFilePath string) error {
	// Create a temporary openssl configuration file that tells how the certificate should look like
	confFile, err := ioutil.TempFile("", "cryptctl-openssl-conf")
	if err != nil {
		return fmt.Errorf("GenerateSelfSignedCertificate: failed to create temporary file - %v", err)
	}
	confFilePath := path.Join("", confFile.Name())
	defer os.Remove(confFilePath)
	confFileContent := fmt.Sprintf(`
[ req ]
distinguished_name = req_distinguished_name
req_extensions     = v3_ca
prompt             = no
[ req_distinguished_name ]
countryName            = FI
localityName           = Testing City
organizationalUnitName = Testing Unit
commonName             = %s
emailAddress           = testing@example.com
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = critical, CA:true
`, commonName)
	if err = ioutil.WriteFile(confFilePath, []byte(confFileContent), 0400); err != nil {
		return fmt.Errorf("GenerateSelfSignedCertificate: failed to write temporary file - %v", err)
	}
	// Generate certificate and key
	if _, statErr := os.Stat(certFilePath); !os.IsNotExist(statErr) {
		return fmt.Errorf("GenerateSelfSignedCertificate: certificate file \"%s\" probably already exists", certFilePath)
	}
	if _, statErr := os.Stat(keyFilePath); !os.IsNotExist(statErr) {
		return fmt.Errorf("GenerateSelfSignedCertificate: key file \"%s\" probably already exists", keyFilePath)
	}
	_, stdout, stderr, err := sys.Exec(nil, nil, nil, BIN_OPENSSL, "req", "-new", "-x509",
		"-config", confFilePath,
		"-newkey", "rsa:2048", "-days", "30", "-nodes",
		"-out", certFilePath, "-keyout", keyFilePath)
	if err != nil {
		return fmt.Errorf("GenerateSelfSignedCertificate: failed to call openssl - %v %s %s", err, stdout, stderr)
	}
	return nil
}
