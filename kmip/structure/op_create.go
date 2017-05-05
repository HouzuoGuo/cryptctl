package structure

import (
	"fmt"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
)

// KMIP request message 420078
type SCreateRequest struct {
	SRequestHeader    SRequestHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SRequestBatchItem SRequestBatchItem // payload is SRequestPayloadCreate
}

func (createReq SCreateRequest) SerialiseToTTLV() ttlv.Item {
	createReq.SRequestHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagRequestMessage, createReq.SRequestHeader.SerialiseToTTLV(), createReq.SRequestBatchItem.SerialiseToTTLV())
	return ret
}
func (createReq *SCreateRequest) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestMessage, TagRequestHeader, &createReq.SRequestHeader); err != nil {
		return err
	}
	if val := createReq.SRequestHeader.IBatchCount.Value; val != 1 {
		return fmt.Errorf("SCreateRequest.DeserialiseFromTTLV: was expecting exactly 1 item, but received %d instead.", val)
	}
	createReq.SRequestBatchItem = SRequestBatchItem{SRequestPayload: &SRequestPayloadCreate{}}
	if err := DecodeStructItem(in, TagRequestMessage, TagBatchItem, &createReq.SRequestBatchItem); err != nil {
		return err
	}
	return nil
}

// 420079
type SRequestPayloadCreate struct {
	EObjectType        ttlv.Enumeration   // 420057
	STemplateAttribute STemplateAttribute // 420091
}

func (createPayload SRequestPayloadCreate) SerialiseToTTLV() ttlv.Item {
	createPayload.EObjectType.Tag = TagObjectType
	return ttlv.NewStructure(TagRequestPayload, &createPayload.EObjectType, createPayload.STemplateAttribute.SerialiseToTTLV())
}
func (createPayload *SRequestPayloadCreate) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestPayload, TagObjectType, &createPayload.EObjectType); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagRequestPayload, TagTemplateAttribute, &createPayload.STemplateAttribute); err != nil {
		return err
	}
	return nil
}

// 42000b of a create request's payload attribute called "Name"
type SCreateRequestNameAttributeValue struct {
	TKeyName ttlv.Text        // 420055
	EKeyType ttlv.Enumeration // 420054
}

func (nameAttr SCreateRequestNameAttributeValue) SerialiseToTTLV() ttlv.Item {
	nameAttr.TKeyName.Tag = TagNameValue
	nameAttr.EKeyType.Tag = TagNameType
	return ttlv.NewStructure(TagAttributeValue, &nameAttr.TKeyName, &nameAttr.EKeyType)
}
func (nameAttr *SCreateRequestNameAttributeValue) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagAttribute, TagNameValue, &nameAttr.TKeyName); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagAttribute, TagNameType, &nameAttr.EKeyType); err != nil {
		return err
	}
	return nil
}

// KMIP response message 42007b
type SCreateResponse struct {
	SResponseHeader    SResponseHeader // IBatchCount is assumed to be 1 in serialisation operations
	SResponseBatchItem SResponseBatchItem
}

func (createResp SCreateResponse) SerialiseToTTLV() ttlv.Item {
	createResp.SResponseHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagResponseMessage, createResp.SResponseHeader.SerialiseToTTLV(), createResp.SResponseBatchItem.SerialiseToTTLV())
	return ret
}
func (createResp *SCreateResponse) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponseMessage, TagResponseHeader, &createResp.SResponseHeader); err != nil {
		return err
	}
	if val := createResp.SResponseHeader.IBatchCount.Value; val != 1 {
		return fmt.Errorf("SCreateResponse.DeserialiseFromTTLV: was expecting exactly 1 item, but received %d instead.", val)
	}
	createResp.SResponseBatchItem = SResponseBatchItem{SResponsePayload: &SResponsePayloadCreate{}}
	if err := DecodeStructItem(in, TagResponseMessage, TagBatchItem, &createResp.SResponseBatchItem); err != nil {
		return err
	}
	return nil
}

// 42007c - response payload from a create response
type SResponsePayloadCreate struct {
	EObjectType ttlv.Enumeration // 420057
	TUniqueID   ttlv.Text        // 420094
}

func (createPayload SResponsePayloadCreate) SerialiseToTTLV() ttlv.Item {
	createPayload.EObjectType.Tag = TagObjectType
	createPayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagResponsePayload, &createPayload.EObjectType, &createPayload.TUniqueID)
}
func (createPayload *SResponsePayloadCreate) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponsePayload, TagObjectType, &createPayload.EObjectType); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponsePayload, TagUniqueID, &createPayload.TUniqueID); err != nil {
		return err
	}
	return nil
}
