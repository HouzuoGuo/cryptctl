package structure

import (
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"reflect"
	"testing"
)

func TestSimpleSerialiseDeserialise(t *testing.T) {
	// Hand-craft a simple structure
	ttlvStruct := &ttlv.Structure{
		TTL: ttlv.TTL{
			Tag: TagResponsePayload,
			Typ: ttlv.TypStruct,
		},
		Items: []interface{}{
			&ttlv.Text{
				TTL: ttlv.TTL{
					Tag: TagUniqueID,
					Typ: ttlv.TypeText,
				},
				Value: "test value",
			},
		},
	}
	// Length of TTLV items is automatically calculated during encoding process
	ttlvBytes := ttlv.EncodeAny(ttlvStruct)
	// Deserialise into a simple payload
	simplePayload := SResponsePayloadDelete{}
	if err := simplePayload.DeserialiseFromTTLV(ttlvStruct); err != nil {
		t.Fatal(err)
	}

	// Reverse the process
	ttlvStructRecovered := simplePayload.SerialiseToTTLV()
	t.Log(ttlv.DebugTTLVItem(0, ttlvStructRecovered))
	// Serialise the reversed structure and match byte binary
	ttlvBytesRecovered := ttlv.EncodeAny(ttlvStructRecovered)
	if !reflect.DeepEqual(ttlvBytes, ttlvBytesRecovered) {
		t.Fatal("mismatch!!!")
	}
	t.Logf("%+v", simplePayload)
}

func TestStructureSerialiseDeserialise(t *testing.T) {
	ttlvCreateReq, _, err := ttlv.DecodeAny(ttlv.SampleCreateRequest)
	if err != nil {
		t.Fatal(err)
	}
	createReq := SCreateRequest{}
	if err := createReq.DeserialiseFromTTLV(ttlvCreateReq); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", createReq)
	ttlvCreateResp, _, err := ttlv.DecodeAny(ttlv.SampleCreateResponse)
	if err != nil {
		t.Fatal(err)
	}
	createResp := SCreateResponse{}
	if err := createResp.DeserialiseFromTTLV(ttlvCreateResp); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", createResp)
	ttlvGetReq, _, err := ttlv.DecodeAny(ttlv.SampleGetRequest)
	if err != nil {
		t.Fatal(err)
	}
	getReq := SGetRequest{}
	if err := getReq.DeserialiseFromTTLV(ttlvGetReq); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", getReq)
	ttlvGetResp, _, err := ttlv.DecodeAny(ttlv.SampleGetResponse)
	if err != nil {
		t.Fatal(err)
	}
	getResp := SGetResponse{}
	if err := getResp.DeserialiseFromTTLV(ttlvGetResp); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", getResp)
	ttlvDestroyReq, _, err := ttlv.DecodeAny(ttlv.SampleDestroyRequest)
	if err != nil {
		t.Fatal(err)
	}
	destroyReq := SDestroyRequest{}
	if err := destroyReq.DeserialiseFromTTLV(ttlvDestroyReq); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", destroyReq)
	ttlvDestroyResp, _, err := ttlv.DecodeAny(ttlv.SampleDestroyResponse)
	if err != nil {
		t.Fatal(err)
	}
	destroyResp := SDestroyResponse{}
	if err := destroyResp.DeserialiseFromTTLV(ttlvDestroyResp); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", destroyResp)
}
