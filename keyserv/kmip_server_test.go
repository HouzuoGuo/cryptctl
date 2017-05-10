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
