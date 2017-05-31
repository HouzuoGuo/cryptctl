// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package ttlv

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

func TestRoundUpTo8(t *testing.T) {
	if i := RoundUpTo8(1); i != 8 {
		t.Fatal(i)
	}
	if i := RoundUpTo8(8); i != 8 {
		t.Fatal(i)
	}
	if i := RoundUpTo8(9); i != 16 {
		t.Fatal(i)
	}
}

func TestCopyValue(t *testing.T) {
	if err := CopyPrimitive(nil, nil); err == nil {
		t.Fatal("did not error")
	}
	i1 := Integer{Value: 1}
	i2 := Integer{}
	if err := CopyPrimitive(&i2, &i1); err != nil || i2.Value != 1 {
		t.Fatal(err, i2)
	}
	long1 := LongInteger{Value: 2}
	long2 := LongInteger{}
	if err := CopyPrimitive(&long2, &long1); err != nil || long2.Value != 2 {
		t.Fatal(err, long2)
	}
	// Must not permit copying across different types
	if err := CopyPrimitive(&i2, &long1); err == nil || i2.Value != 1 {
		t.Fatal("did not error")
	}
	enum1 := Enumeration{Value: 3}
	enum2 := Enumeration{}
	if err := CopyPrimitive(&enum2, &enum1); err != nil || enum2.Value != 3 {
		t.Fatal(err, enum2)
	}
	dt1 := DateTime{Time: time.Unix(4, 0)}
	dt2 := DateTime{}
	if err := CopyPrimitive(&dt2, &dt1); err != nil || dt2.Time.Unix() != 4 {
		t.Fatal(err, dt2)
	}
	text1 := Text{Value: "5"}
	text2 := Text{}
	if err := CopyPrimitive(&text2, &text1); err != nil || text2.Value != "5" {
		t.Fatal(err, text2)
	}
	bytes1 := Bytes{Value: []byte{6}}
	bytes2 := Bytes{}
	if err := CopyPrimitive(&bytes2, &bytes1); err != nil || len(bytes2.Value) != 1 || bytes2.Value[0] != 6 {
		t.Fatal(err, bytes2)
	}
}

func TestEncodeDecode(t *testing.T) {
	for i, data := range [][]byte{
		SampleCreateRequest, SampleCreateResponseSuccess,
		SampleGetRequest, SampleGetResponseSuccess, SampleGetResponseFailure,
		SampleDestroyRequest, SampleDestroyResponseSuccess, SampleDestroyResponseFailure,
	} {
		decoded, _, err := DecodeAny(data)
		t.Log(DebugTTLVItem(0, decoded))
		if err != nil {
			t.Fatal(err)
		}
		encoded := EncodeAny(decoded)
		if !reflect.DeepEqual(data, encoded) {
			t.Fatalf("Mismatch in %d:\n%s\n\n%s\n", i, hex.Dump(data), hex.Dump(encoded))
		}
	}
}
