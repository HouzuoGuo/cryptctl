// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package ttlv

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	TypStruct    = 0x1
	TypInt       = 0x2
	TypLong      = 0x3
	TypeEnum     = 0x5
	TypeText     = 0x7
	TypeBytes    = 0x8
	TypeDateTime = 0x9
	LenTTL       = 3 + 1 + 4 // 3 bytes of tag, 1 byte of type, 4 bytes of length
)

// All TTLV items implement this interface.
type Item interface {
	GetTTL() TTL    // Return TTL component of TTLV item.
	GetLength() int // Calculate value length and give the length to TTL. Apart from Structure, the length does not count padding.
	ResetTyp()      // Reset Typ byte in TTL structure to the one corresponding to implementation.
}

type Tag [3]byte // The tag of TTLV consists of three bytes

// Syntactic sugar to return byte slice equivalent of the tag.
func (tag Tag) ByteSlice() []byte {
	return tag[:]
}

// Bytes, type, and value length excluding padding.
type TTL struct {
	Tag    Tag
	Typ    byte
	Length int
}

// Return tag, type, and length in a string.
func (com TTL) TTLString() string {
	return fmt.Sprintf("TAG %s TYP %d LEN %d", hex.EncodeToString(com.Tag[:]), com.Typ, com.Length)
}

// Write tag bytes and type byte into the buffer.
func (com TTL) WriteTTTo(out *bytes.Buffer) {
	out.Write(com.Tag[:])
	out.WriteByte(com.Typ)
}

// TTLV structure. Length of value is sum of item lengths including padding.
type Structure struct {
	TTL
	Items []Item
}

func (st *Structure) GetTTL() TTL {
	return st.TTL
}

func (st *Structure) GetLength() int {
	newLen := 0
	for _, item := range st.Items {
		// Structure length counts individual item's TTL
		newLen += LenTTL
		// Item value length does not include padding
		itemLen := item.GetLength()
		// But structure length counts padding
		newLen += RoundUpTo8(itemLen)
	}
	st.Length = newLen
	return newLen
}

func (st *Structure) ResetTyp() {
	st.Typ = TypStruct
}

// Construct a new structure with the specified tag, place the items inside the structure as well. Each item must be a pointer to Item.
func NewStructure(tag Tag, items ...Item) *Structure {
	ret := &Structure{TTL: TTL{Tag: tag, Typ: TypStruct}, Items: make([]Item, 0, 8)}
	for _, item := range items {
		ret.Items = append(ret.Items, item)
	}
	return ret
}

// TTLV integer. Length of value is 4. Representation comes with 4 additional bytes of padding.
type Integer struct {
	TTL
	Value int32
}

func (i *Integer) GetTTL() TTL {
	return i.TTL
}

func (i *Integer) GetLength() int {
	i.Length = 4
	return 4
}
func (i *Integer) ResetTyp() {
	i.Typ = TypInt
}

// TTLV long integer. Length of value is 8.
type LongInteger struct {
	TTL
	Value int64
}

func (li *LongInteger) GetTTL() TTL {
	return li.TTL
}

func (li *LongInteger) GetLength() int {
	li.Length = 8
	return 8
}
func (li *LongInteger) ResetTyp() {
	li.Typ = TypLong
}

// TTLV enumeration. Length of value is 4. Representation comes with 4 additional bytes of padding.
type Enumeration struct {
	TTL
	Value int32
}

func (enum *Enumeration) GetTTL() TTL {
	return enum.TTL
}

func (enum *Enumeration) GetLength() int {
	enum.Length = 4
	return 4
}
func (enum *Enumeration) ResetTyp() {
	enum.Typ = TypeEnum
}

// TTLV date time - seconds since Unix epoch represented as LongInteger. Length of value is 8.
type DateTime struct {
	TTL
	Time time.Time
}

func (dt *DateTime) GetTTL() TTL {
	return dt.TTL
}

func (dt *DateTime) GetLength() int {
	dt.Length = 8
	return 8
}
func (dt *DateTime) ResetTyp() {
	dt.Typ = TypeDateTime
}

// TTLV text string. Length of value is actual string length, but representation is padded to align with 8 bytes.
type Text struct {
	TTL
	Value string
}

func (text *Text) GetTTL() TTL {
	return text.TTL
}

func (text *Text) GetLength() int {
	text.Length = len(text.Value)
	return text.Length
}
func (text *Text) ResetTyp() {
	text.Typ = TypeText
}

// TTLV byte array. Length of value is actual array length, but representation is padded to align with 8 bytes.
type Bytes struct {
	TTL
	Value []byte
}

func (bytes *Bytes) GetTTL() TTL {
	return bytes.TTL
}

func (bytes *Bytes) GetLength() int {
	bytes.Length = len(bytes.Value)
	return bytes.Length
}
func (bytes *Bytes) ResetTyp() {
	bytes.Typ = TypeBytes
}
