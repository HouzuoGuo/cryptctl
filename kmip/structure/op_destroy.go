package structure

import "github.com/HouzuoGuo/cryptctl/kmip/ttlv"

// KMIP request message 420078
type SDestroyRequest struct {
	SRequestHeader    SRequestHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SRequestBatchItem SRequestBatchItem // payload is SRequestPayloadDestroy
}

func (destroyReq *SDestroyRequest) SerialiseToTTLV() ttlv.Item {
	destroyReq.SRequestHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagRequestMessage, destroyReq.SRequestHeader.SerialiseToTTLV(), destroyReq.SRequestBatchItem.SerialiseToTTLV())
	return ret
}
func (destroyReq *SDestroyRequest) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestMessage, TagRequestHeader, &destroyReq.SRequestHeader); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagRequestMessage, TagBatchItem, &destroyReq.SRequestBatchItem); err != nil {
		return err
	}
	return nil
}

// 420079 - request payload from a delete request
type SRequestPayloadDestroy struct {
	TUniqueID ttlv.Text // 420094
}

func (deletePayload *SRequestPayloadDestroy) SerialiseToTTLV() ttlv.Item {
	deletePayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagRequestPayload, &deletePayload.TUniqueID)
}
func (deletePayload *SRequestPayloadDestroy) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestPayload, TagUniqueID, &deletePayload.TUniqueID); err != nil {
		return err
	}
	return nil
}

// KMIP response message 42007b
type SDestroyResponse struct {
	SHeader            SResponseHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SResponseBatchItem SResponseBatchItem // payload is SResponsePayloadDelete
}

func (destroyResp *SDestroyResponse) SerialiseToTTLV() ttlv.Item {
	destroyResp.SHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagResponseMessage, destroyResp.SHeader.SerialiseToTTLV(), destroyResp.SResponseBatchItem.SerialiseToTTLV())
	return ret
}
func (destroyResp *SDestroyResponse) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponseMessage, TagResponseHeader, &destroyResp.SHeader); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponseMessage, TagBatchItem, &destroyResp.SResponseBatchItem); err != nil {
		return err
	}
	return nil
}

// 42007c - response payload from a delete response
type SResponsePayloadDelete struct {
	TUniqueID ttlv.Text // 420094
}

func (deletePayload *SResponsePayloadDelete) SerialiseToTTLV() ttlv.Item {
	deletePayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagResponsePayload, &deletePayload.TUniqueID)
}
func (deletePayload *SResponsePayloadDelete) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponsePayload, TagUniqueID, &deletePayload.TUniqueID); err != nil {
		return err
	}
	return nil
}
