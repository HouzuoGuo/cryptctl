package structure

import (
	"encoding/hex"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"reflect"
	"testing"
)

func TestSerialiseSimpleStruct(t *testing.T) {
	// Hand-craft a SCredential
	ttlvStruct := &ttlv.Structure{
		TTL: ttlv.TTL{
			Tag: TagCredential,
			Typ: ttlv.TypStruct,
		},
		Items: []interface{}{
			&ttlv.Enumeration{
				TTL: ttlv.TTL{
					Tag: TagCredentialType,
					Typ: ttlv.TypeEnum,
				},
				Value: 1,
			},
			&ttlv.Structure{
				TTL: ttlv.TTL{
					Tag: TagCredentialValue,
					Typ: ttlv.TypStruct,
				},
				Items: []interface{}{
					&ttlv.Text{
						TTL: ttlv.TTL{
							Tag: TagUsername,
							Typ: ttlv.TypeText,
						},
						Value: "user",
					},
					&ttlv.Text{
						TTL: ttlv.TTL{
							Tag: TagPassword,
							Typ: ttlv.TypeText,
						},
						Value: "pass",
					},
				},
			},
		},
	}
	// Length of TTLV items is automatically calculated during encoding process
	ttlvBytes := ttlv.EncodeAny(ttlvStruct)
	// Deserialise into a SCredential
	cred := SCredential{}
	if err := cred.DeserialiseFromTTLV(ttlvStruct); err != nil {
		t.Fatal(err)
	}
	t.Logf("Encoded:\n%s", ttlv.DebugTTLVItem(0, ttlvStruct))
	t.Logf("Deserialised:\n%+v", cred)

	// Reverse the process
	ttlvStructRecovered := cred.SerialiseToTTLV()
	t.Logf("Recovered:\n%s", ttlv.DebugTTLVItem(0, ttlvStructRecovered))
	// Serialise the reversed structure and match byte binary
	ttlvBytesRecovered := ttlv.EncodeAny(ttlvStructRecovered)
	fmt.Println(hex.Dump(ttlvBytes))
	fmt.Println(hex.Dump(ttlvBytesRecovered))
	if !reflect.DeepEqual(ttlvBytes, ttlvBytesRecovered) {
		t.Fatal("mismatch in binary representation")
	}
}

func TestSerialiseStruct(t *testing.T) {
	structs := []SerialisedItem{
		&SCreateRequest{}, &SCreateResponse{},
		&SGetRequest{}, &SGetResponse{}, &SGetResponse{},
		&SDestroyRequest{}, &SDestroyResponse{}, &SDestroyResponse{},
	}
	binaries := [][]byte{
		ttlv.SampleCreateRequest, ttlv.SampleCreateResponseSuccess,
		ttlv.SampleGetRequest, ttlv.SampleGetResponseSuccess, ttlv.SampleGetResponseFailure,
		ttlv.SampleDestroyRequest, ttlv.SampleDestroyResponseSuccess, ttlv.SampleDestroyResponseFailure,
	}
	ttlvs := make([]ttlv.Item, len(binaries))

	for i, bin := range binaries {
		fmt.Printf("====================\n%d\n====================\n", i)
		var err error
		// bin -> ttlv
		ttlvs[i], _, err = ttlv.DecodeAny(bin)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Input binary:\n%s\n", hex.Dump(bin))
		fmt.Printf("Input TTLV:\n%s\n", ttlv.DebugTTLVItem(0, ttlvs[i]))
		// ttlv -> struct
		err = structs[i].DeserialiseFromTTLV(ttlvs[i])
		if err != nil {
			t.Fatal(err)
		}
		/*
			debugJson, err := json.MarshalIndent(structs[i], "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("Input struct:\n%s\n", string(debugJson))
		*/
		// reverse the operations above
		recoveredTTLV := structs[i].SerialiseToTTLV()
		fmt.Printf("Recovered TTLV:\n%s\n", ttlv.DebugTTLVItem(0, recoveredTTLV))
		recoveredBin := ttlv.EncodeAny(recoveredTTLV)
		fmt.Printf("Recovered binary:\n%s\n", hex.Dump(recoveredBin))
		if !reflect.DeepEqual(bin, recoveredBin) {
			t.Fatal("mismatch in binary representation")
		}
	}
}
