package structure

import "github.com/HouzuoGuo/cryptctl/kmip/ttlv"

// KMIP request message 420078
type SGetRequest struct {
	SRequestHeader    SRequestHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SRequestBatchItem SRequestBatchItem // payload is SRequestPayloadGet
}

func (getReq *SGetRequest) SerialiseToTTLV() ttlv.Item {
	getReq.SRequestHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagRequestMessage, getReq.SRequestHeader.SerialiseToTTLV(), getReq.SRequestBatchItem.SerialiseToTTLV())
	return ret
}
func (getReq *SGetRequest) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestMessage, TagRequestHeader, &getReq.SRequestHeader); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagRequestMessage, TagBatchItem, &getReq.SRequestBatchItem); err != nil {
		return err
	}
	return nil
}

// 420079 - request payload from a get request
type SRequestPayloadGet struct {
	TUniqueID ttlv.Text // 420094
}

func (getPayload *SRequestPayloadGet) SerialiseToTTLV() ttlv.Item {
	getPayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagRequestPayload, &getPayload.TUniqueID)
}
func (getPayload *SRequestPayloadGet) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestPayload, TagUniqueID, &getPayload.TUniqueID); err != nil {
		return err
	}
	return nil
}

// KMIP response message 42007b
type SGetResponse struct {
	SHeader            SResponseHeader    // IBatchCount is assumed to be 1 in serialisation operations
	SResponseBatchItem SResponseBatchItem // payload is SResponsePayloadGet
}

func (getResp *SGetResponse) SerialiseToTTLV() ttlv.Item {
	getResp.SHeader.IBatchCount.Value = 1
	ret := ttlv.NewStructure(TagResponseMessage, getResp.SHeader.SerialiseToTTLV(), getResp.SResponseBatchItem.SerialiseToTTLV())
	return ret
}
func (getResp *SGetResponse) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponseMessage, TagResponseHeader, &getResp.SHeader); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponseMessage, TagBatchItem, &getResp.SResponseBatchItem); err != nil {
		return err
	}
	return nil
}

// 42007c - response payload from a get response
type SResponsePayloadGet struct {
	EObjectType   ttlv.Enumeration // 420057
	TUniqueID     ttlv.Text        // 420094
	SSymmetricKey SSymmetricKey
}

func (getPayload *SResponsePayloadGet) SerialiseToTTLV() ttlv.Item {
	getPayload.EObjectType.Tag = TagObjectType
	getPayload.TUniqueID.Tag = TagUniqueID
	return ttlv.NewStructure(TagResponsePayload, &getPayload.EObjectType, &getPayload.TUniqueID, getPayload.SSymmetricKey.SerialiseToTTLV())
}
func (getPayload *SResponsePayloadGet) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponsePayload, TagObjectType, &getPayload.EObjectType); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponsePayload, TagUniqueID, &getPayload.TUniqueID); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponsePayload, TagSymmetricKey, &getPayload.SSymmetricKey); err != nil {
		return err
	}
	return nil
}

// 42008f
type SSymmetricKey struct {
	SKeyBlock SKeyBlock
}

func (symKey *SSymmetricKey) SerialiseToTTLV() ttlv.Item {
	return ttlv.NewStructure(TagSymmetricKey, symKey.SKeyBlock.SerialiseToTTLV())
}
func (symKey *SSymmetricKey) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagSymmetricKey, TagKeyBlock, &symKey.SKeyBlock); err != nil {
		return err
	}
	return nil
}

// 420040
type SKeyBlock struct {
	EFormatType      ttlv.Enumeration // 420042
	SKeyValue        SKeyValue
	ECryptoAlgorithm ttlv.Enumeration // 420028
	ECryptoLen       ttlv.Integer     // 42002a
}

func (block *SKeyBlock) SerialiseToTTLV() ttlv.Item {
	block.EFormatType.Tag = TagFormatType
	block.ECryptoAlgorithm.Tag = TagCryptoAlgorithm
	block.ECryptoLen.Tag = TagCryptoLen
	return ttlv.NewStructure(TagKeyBlock, &block.EFormatType, block.SKeyValue.SerialiseToTTLV(), &block.ECryptoAlgorithm, &block.ECryptoLen)
}
func (block *SKeyBlock) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagKeyBlock, TagFormatType, &block.EFormatType); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagKeyBlock, TagKeyValue, &block.SKeyValue); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagKeyBlock, TagCryptoAlgorithm, &block.ECryptoAlgorithm); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagKeyBlock, TagCryptoLen, &block.ECryptoLen); err != nil {
		return err
	}
	return nil
}

// 420045 - this is value of an encryption key, not to be confused with a key-value pair.
type SKeyValue struct {
	BKeyMaterial ttlv.Bytes // 420043
}

func (key *SKeyValue) SerialiseToTTLV() ttlv.Item {
	key.BKeyMaterial.Tag = TagKeyMaterial
	return ttlv.NewStructure(TagKeyValue, &key.BKeyMaterial)
}

func (key *SKeyValue) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagKeyValue, TagKeyMaterial, &key.BKeyMaterial); err != nil {
		return err
	}
	return nil
}
