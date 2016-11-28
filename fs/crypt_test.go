// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package fs

import "testing"

// The unit test simply makes sure that the functions do not crash, it does not set up an encrypted device node.
func TestCryptSetup(t *testing.T) {
	if err := CryptFormat([]byte{}, "doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
	if err := CryptOpen([]byte{}, "doesnotexist", "doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
	if mapping, err := CryptStatus("doesnotexist"); err == nil || mapping.Device != "" {
		t.Fatal("did not error")
	}
	if err := CryptClose("doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
	if err := CryptErase("doesnotexist"); err == nil {
		t.Fatal("did not error")
	}
}

func TestParseCryptStatus(t *testing.T) {
	sample1 := `/dev/mapper/howard-enc is active and is in use.
  type:    LUKS1
  cipher:  aes-xts-plain64
  keysize: 256 bits
  device:  /dev/loop0
  loop:    /my-loop-file
  offset:  4096 sectors
  size:    24571904 sectors
  mode:    read/write
`
	expected := CryptMapping{
		Type:    "LUKS1",
		Cipher:  "aes-xts-plain64",
		KeySize: 256,
		Device:  "/dev/loop0",
		Loop:    "/my-loop-file",
	}
	if parsed := ParseCryptStatus(sample1); parsed != expected || !parsed.IsValid() {
		t.Fatalf("%+v", parsed)
	}
	sample2 := `/dev/mapper/cryptopened is active.
Oops, secure memory pool already initialized
  type:    LUKS1
  cipher:  aes-xts-plain64
  keysize: 256 bits
  device:  /dev/vdc
  offset:  4096 sectors
  size:    18870272 sectors
  mode:    read/write
	`
	expected = CryptMapping{
		Type:    "LUKS1",
		Cipher:  "aes-xts-plain64",
		KeySize: 256,
		Device:  "/dev/vdc",
		Loop:    "",
	}
	if parsed := ParseCryptStatus(sample2); parsed != expected || !parsed.IsValid() {
		t.Fatalf("%+v", parsed)
	}
}
