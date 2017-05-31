// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package structure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"reflect"
)

// Match input structure pointer against expected structure tag, then look for an item with matching item tag and return.
func FindStructItem(structPtr ttlv.Item, structTag, itemTag ttlv.Tag) (ttlv.Item, error) {
	if structPtr == nil {
		return nil, errors.New("FindStructItem: structPtr is nil")
	}
	var st *ttlv.Structure
	var isStructure bool
	if st, isStructure = structPtr.(*ttlv.Structure); !isStructure {
		return nil, fmt.Errorf("FindStructItem: thing is a %s, it is not a structure pointer.", reflect.TypeOf(structPtr).String())
	}
	if st.Tag != structTag {
		return nil, fmt.Errorf("FindStructItem: was expecting structure tag to be %s, but got %s instead.", hex.EncodeToString(structTag[:]), hex.EncodeToString(st.GetTTL().Tag.ByteSlice()))
	}
	// Find structure item that matches specified tag
	var matchedItem ttlv.Item // pointer to item
	for _, item := range st.Items {
		if item.(ttlv.Item).GetTTL().Tag == itemTag {
			matchedItem = item.(ttlv.Item) // already a pointer to item
			break
		}
	}
	if matchedItem == nil {
		return nil, fmt.Errorf("FindStructItem: cannot find an item with tag %s in structure %s", hex.EncodeToString(itemTag[:]), hex.EncodeToString(st.Tag[:]))
	}
	return matchedItem, nil
}

/*
Match input structure pointer against expected structure tag, then look for an item with matching item tag
and calls receiver to decode itself from the item with matching tag.
*/
func DecodeStructItem(structPtr ttlv.Item, structTag, itemTag ttlv.Tag, serialsableOrTTLVItemPtr interface{}) error {
	if structPtr == nil {
		return errors.New("DecodeStructItem: structPtr is nil")
	}
	var st *ttlv.Structure
	var isStructure bool
	if st, isStructure = structPtr.(*ttlv.Structure); !isStructure {
		return fmt.Errorf("DecodeStructItem: thing is a %s, it is not a structure pointer.", reflect.TypeOf(structPtr).String())
	}
	if st.Tag != structTag {
		return fmt.Errorf("DecodeStructItem: was expecting structure tag to be %s, but got %s instead.", hex.EncodeToString(structTag[:]), hex.EncodeToString(st.GetTTL().Tag.ByteSlice()))
	}
	// Find structure item that matches specified tag
	var matchedItem ttlv.Item // pointer to item
	for _, item := range st.Items {
		if item == nil {
			continue
		}
		if item.(ttlv.Item).GetTTL().Tag == itemTag {
			matchedItem = item.(ttlv.Item) // already a pointer to item
			break
		}
	}
	if matchedItem == nil {
		return fmt.Errorf("DecodeStructItem: cannot find an item with tag %s in structure %s", hex.EncodeToString(itemTag[:]), hex.EncodeToString(st.Tag[:]))
	}
	switch receiver := serialsableOrTTLVItemPtr.(type) {
	case *SerialisedItem:
		derefReceiver := *receiver
		return derefReceiver.DeserialiseFromTTLV(matchedItem)
	case SerialisedItem:
		return receiver.DeserialiseFromTTLV(matchedItem)
	case ttlv.Item:
		return ttlv.CopyPrimitive(receiver, matchedItem)
	default:
		return fmt.Errorf("DecodeStructItem: does not know how to decode into receiver of type %s", reflect.TypeOf(serialsableOrTTLVItemPtr).String())
	}
}

/*
Match input structure pointer against expected structure tag, then look for items with matching item tag
and calls receiver function to decode each item.
*/
func DecodeStructItems(structPtr ttlv.Item, structTag, itemTag ttlv.Tag, makeReceiver func() interface{}, afterReceiver func(interface{})) error {
	if structPtr == nil {
		return errors.New("DecodeStructItems: structPtr is nil")
	}
	var st *ttlv.Structure
	var isStructure bool
	if st, isStructure = structPtr.(*ttlv.Structure); !isStructure {
		return fmt.Errorf("DecodeStructItems: thing is a %s, it is not a structure pointer.", reflect.TypeOf(structPtr).String())
	}
	if st.Tag != structTag {
		return fmt.Errorf("DecodeStructItems: was expecting structure tag to be %s, but got %s instead.", hex.EncodeToString(structTag[:]), hex.EncodeToString(st.GetTTL().Tag.ByteSlice()))
	}
	// Find items that match specified tag, and call function on each one.
	for _, item := range st.Items {
		if item == nil {
			continue
		}
		ttlvItem := item.(ttlv.Item)
		if ttlvItem.GetTTL().Tag == itemTag {
			var err error
			serialsableOrTTLVItemPtr := makeReceiver()
			switch receiver := serialsableOrTTLVItemPtr.(type) {
			case SerialisedItem:
				err = receiver.DeserialiseFromTTLV(ttlvItem)
			case ttlv.Item:
				err = ttlv.CopyPrimitive(receiver, ttlvItem)
			default:
				err = fmt.Errorf("DecodeStructItems: does not know how to decode into receiver of type %s", reflect.TypeOf(serialsableOrTTLVItemPtr).String())
			}
			if err != nil {
				return err
			}
			afterReceiver(serialsableOrTTLVItemPtr)
		}
	}
	return nil
}

// All structures can be encoded to and decoded from TTLV items.
type SerialisedItem interface {
	SerialiseToTTLV() ttlv.Item          // Return reference to encoded TTLV item. The length of encoded item must not be touched, because EncodeAny() eventually calculates the length.
	DeserialiseFromTTLV(ttlv.Item) error // Parameter is reference to TTLV item. The length of TTLV item must not be used.
}

// 420077
type SRequestHeader struct {
	SProtocolVersion SProtocolVersion
	SAuthentication  SAuthentication
	IBatchCount      ttlv.Integer // 42000d
}

func (header SRequestHeader) SerialiseToTTLV() ttlv.Item {
	header.IBatchCount.Tag = TagBatchCount
	return ttlv.NewStructure(
		TagRequestHeader,
		header.SProtocolVersion.SerialiseToTTLV(),
		header.SAuthentication.SerialiseToTTLV(),
		&header.IBatchCount)
}

func (header *SRequestHeader) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagRequestHeader, TagProtocolVersion, &header.SProtocolVersion); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagRequestHeader, TagAuthentication, &header.SAuthentication); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagRequestHeader, TagBatchCount, &header.IBatchCount); err != nil {
		return err
	}
	return nil
}

// 420069
type SProtocolVersion struct {
	IMajor ttlv.Integer // 42006a
	IMinor ttlv.Integer // 42006b
}

func (ver SProtocolVersion) SerialiseToTTLV() ttlv.Item {
	ver.IMajor.Tag = TagProtocolVersionMajor
	ver.IMinor.Tag = TagProtocolVersionMinor
	return ttlv.NewStructure(
		TagProtocolVersion,
		&ver.IMajor,
		&ver.IMinor)
}

func (ver *SProtocolVersion) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagProtocolVersion, TagProtocolVersionMajor, &ver.IMajor); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagProtocolVersion, TagProtocolVersionMinor, &ver.IMinor); err != nil {
		return err
	}
	return nil
}

// 42000c
type SAuthentication struct {
	SCredential SCredential
}

func (auth SAuthentication) SerialiseToTTLV() ttlv.Item {
	return ttlv.NewStructure(TagAuthentication, auth.SCredential.SerialiseToTTLV())
}

func (auth *SAuthentication) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagAuthentication, TagCredential, &auth.SCredential); err != nil {
		return err
	}
	return nil
}

// 420023. Assume credential type is 1, i.e. username + password.
type SCredential struct {
	ICredentialType  ttlv.Enumeration // 420024. value is 1 - username + password
	SCredentialValue SCredentialValueUsernamePassword
}

func (cred SCredential) SerialiseToTTLV() ttlv.Item {
	cred.ICredentialType.Tag = TagCredentialType
	cred.ICredentialType.Value = 1 // username + password
	return ttlv.NewStructure(TagCredential, &cred.ICredentialType, cred.SCredentialValue.SerialiseToTTLV())
}

func (cred *SCredential) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagCredential, TagCredentialType, &cred.ICredentialType); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagCredential, TagCredentialValue, &cred.SCredentialValue); err != nil {
		return err
	}
	return nil
}

// 420025
type SCredentialValueUsernamePassword struct {
	TUsername ttlv.Text // 420099
	TPassword ttlv.Text // 4200a1
}

func (pass SCredentialValueUsernamePassword) SerialiseToTTLV() ttlv.Item {
	pass.TUsername.Tag = TagUsername
	pass.TPassword.Tag = TagPassword
	return ttlv.NewStructure(TagCredentialValue, &pass.TUsername, &pass.TPassword)
}

func (pass *SCredentialValueUsernamePassword) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagCredentialValue, TagUsername, &pass.TUsername); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagCredentialValue, TagPassword, &pass.TPassword); err != nil {
		return err
	}
	return nil
}

// 42000f of a request
type SRequestBatchItem struct {
	EOperation      ttlv.Enumeration // 42005c
	SRequestPayload SerialisedItem   // reference to any 420079
}

func (reqItem SRequestBatchItem) SerialiseToTTLV() ttlv.Item {
	reqItem.EOperation.Tag = TagOperation
	return ttlv.NewStructure(
		TagBatchItem,
		&reqItem.EOperation,
		reqItem.SRequestPayload.SerialiseToTTLV())
}

func (reqItem *SRequestBatchItem) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagBatchItem, TagOperation, &reqItem.EOperation); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagBatchItem, TagRequestPayload, &reqItem.SRequestPayload); err != nil {
		return err
	}
	return nil
}

// 420091
type STemplateAttribute struct {
	Attributes []SAttribute
}

func (tattr STemplateAttribute) SerialiseToTTLV() ttlv.Item {
	ret := ttlv.NewStructure(TagTemplateAttribute)
	for _, attr := range tattr.Attributes {
		ret.Items = append(ret.Items, (&attr).SerialiseToTTLV())
	}
	return ret
}

func (tattr *STemplateAttribute) DeserialiseFromTTLV(in ttlv.Item) error {
	attrs := make([]SAttribute, 0, 4)
	makeReceiver := func() interface{} {
		return &SAttribute{}
	}
	afterReceiver := func(in interface{}) {
		attrs = append(attrs, *in.(*SAttribute))
	}
	if err := DecodeStructItems(in, TagTemplateAttribute, TagAttribute, makeReceiver, afterReceiver); err != nil {
		return err
	}
	tattr.Attributes = attrs
	return nil
}

// 420008
type SAttribute struct {
	TAttributeName ttlv.Text // 42000a
	AttributeValue ttlv.Item // reference to any TTLV item
}

func (attr SAttribute) SerialiseToTTLV() ttlv.Item {
	attr.TAttributeName.Tag = TagAttributeName
	return ttlv.NewStructure(TagAttribute, &attr.TAttributeName, attr.AttributeValue)
}

func (attr *SAttribute) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagAttribute, TagAttributeName, &attr.TAttributeName); err != nil {
		return err
	} else if attr.AttributeValue, err = FindStructItem(in, TagAttribute, TagAttributeValue); err != nil {
		return err
	}
	return nil
}

// 42007a
type SResponseHeader struct {
	SVersion    SProtocolVersion
	TTimestamp  ttlv.DateTime // 420092
	IBatchCount ttlv.Integer  // 42000d
}

func (respHeader SResponseHeader) SerialiseToTTLV() ttlv.Item {
	respHeader.TTimestamp.Tag = TagTimestamp
	respHeader.IBatchCount.Tag = TagBatchCount
	return ttlv.NewStructure(TagResponseHeader, respHeader.SVersion.SerialiseToTTLV(), &respHeader.TTimestamp, &respHeader.IBatchCount)
}

func (respHeader *SResponseHeader) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagResponseHeader, TagProtocolVersion, &respHeader.SVersion); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponseHeader, TagTimestamp, &respHeader.TTimestamp); err != nil {
		return err
	} else if err := DecodeStructItem(in, TagResponseHeader, TagBatchCount, &respHeader.IBatchCount); err != nil {
		return err
	}
	return nil
}

// 42000f of a response message
type SResponseBatchItem struct {
	EOperation       ttlv.Enumeration // 42005c
	EResultStatus    ttlv.Enumeration // 42007f
	EResultReason    ttlv.Enumeration // 42007e
	EResultMessage   ttlv.Text        // 42007d
	SResponsePayload SerialisedItem   // reference to any 42007c
}

func (respItem SResponseBatchItem) SerialiseToTTLV() ttlv.Item {
	respItem.EOperation.Tag = TagOperation
	respItem.EResultStatus.Tag = TagResultStatus
	items := []ttlv.Item{&respItem.EOperation, &respItem.EResultStatus}
	if respItem.EResultStatus.Value == ValResultStatusSuccess {
		items = append(items, respItem.SResponsePayload.SerialiseToTTLV())
	} else {
		respItem.EResultReason.Tag = TagResultReason
		respItem.EResultMessage.Tag = TagResultMessage
		items = append(items, &respItem.EResultReason, &respItem.EResultMessage)
	}
	return ttlv.NewStructure(TagBatchItem, items...)
}

func (respItem *SResponseBatchItem) DeserialiseFromTTLV(in ttlv.Item) error {
	if err := DecodeStructItem(in, TagBatchItem, TagOperation, &respItem.EOperation); err != nil {
		return err
	}
	DecodeStructItem(in, TagBatchItem, TagResultStatus, &respItem.EResultStatus)
	DecodeStructItem(in, TagBatchItem, TagResultReason, &respItem.EResultReason)
	DecodeStructItem(in, TagBatchItem, TagResultMessage, &respItem.EResultMessage)
	DecodeStructItem(in, TagBatchItem, TagResponsePayload, &respItem.SResponsePayload)
	return nil
}
