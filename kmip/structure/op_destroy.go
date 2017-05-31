// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package structure

import (
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
)

// KMIP request message 420078
type SDestroyRequest struct {
	SRequestHeader    SRequestHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SRequestBatchItem SRequestBatchItem // payload is SRequestPayloadDestroy
}

func (destroyReq SDestroyRequest) SerialiseToTTLV() ttlv.Item {
	destroyReq.SRequestHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagRequestMessage, destroyReq.SRequestHeader.SerialiseToTTLV(), destroyReq.SRequestBatchItem.SerialiseToTTLV())
	return ret
}
func (destroyReq *SDestroyRequest) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestMessage, TagRequestHeader, &destroyReq.SRequestHeader); err != nil {
		return err
	}
	if val := destroyReq.SRequestHeader.IBatchCount.Value; val != 1 {
		return fmt.Errorf("SDestroyRequest.DeserialiseFromTTLV: was expecting exactly 1 item, but received %d instead.", val)
	}
	destroyReq.SRequestBatchItem = SRequestBatchItem{SRequestPayload: &SRequestPayloadDestroy{}}
	if err := DecodeStructItem(in, TagRequestMessage, TagBatchItem, &destroyReq.SRequestBatchItem); err != nil {
		return err
	}
	if destroyReq.SRequestBatchItem.EOperation.Value != ValOperationDestroy {
		return errors.New("SDestroyRequest.DeserialiseFromTTLV: input is not a destroy request")
	}
	return nil
}

// 420079 - request payload from a delete request
type SRequestPayloadDestroy struct {
	TUniqueID ttlv.Text // 420094
}

func (deletePayload SRequestPayloadDestroy) SerialiseToTTLV() ttlv.Item {
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
	SResponseHeader    SResponseHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SResponseBatchItem SResponseBatchItem // payload is SResponsePayloadDestroy
}

func (destroyResp SDestroyResponse) SerialiseToTTLV() ttlv.Item {
	destroyResp.SResponseHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagResponseMessage, destroyResp.SResponseHeader.SerialiseToTTLV(), destroyResp.SResponseBatchItem.SerialiseToTTLV())
	return ret
}
func (destroyResp *SDestroyResponse) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponseMessage, TagResponseHeader, &destroyResp.SResponseHeader); err != nil {
		return err
	}
	if val := destroyResp.SResponseHeader.IBatchCount.Value; val != 1 {
		return fmt.Errorf("SDestroyResponse.DeserialiseFromTTLV: was expecting exactly 1 item, but received %d instead.", val)
	}
	destroyResp.SResponseBatchItem = SResponseBatchItem{SResponsePayload: &SResponsePayloadDestroy{}}
	if err := DecodeStructItem(in, TagResponseMessage, TagBatchItem, &destroyResp.SResponseBatchItem); err != nil {
		return err
	}
	if destroyResp.SResponseBatchItem.EOperation.Value != ValOperationDestroy {
		return errors.New("SDestroyResponse.DeserialiseFromTTLV: input is not a destroy response")
	}
	return nil
}

// 42007c - response payload from a destroy response
type SResponsePayloadDestroy struct {
	TUniqueID ttlv.Text // 420094
}

func (deletePayload SResponsePayloadDestroy) SerialiseToTTLV() ttlv.Item {
	deletePayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagResponsePayload, &deletePayload.TUniqueID)
}
func (deletePayload *SResponsePayloadDestroy) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponsePayload, TagUniqueID, &deletePayload.TUniqueID); err != nil {
		return err
	}
	return nil
}
