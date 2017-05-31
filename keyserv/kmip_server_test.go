// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"reflect"
	"testing"
)

func TestGetNewDiskEncryptionKeyBits(t *testing.T) {
	key1 := GetNewDiskEncryptionKeyBits()
	key2 := GetNewDiskEncryptionKeyBits()
	if len(key1) != KMIPAESKeySizeBits/8 || reflect.DeepEqual(key1, key2) {
		t.Fatal(key1, key2)
	}
}
