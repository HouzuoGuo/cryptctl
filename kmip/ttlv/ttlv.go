package ttlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
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

type Tag [3]byte // The tag of TTLV consists of three bytes

// Tag, type, and value length excluding padding.
type TTL struct {
	Tag    Tag
	Typ    byte
	Length int
}

// Return tag, type, and length in a string.
func (com TTL) String() string {
	return fmt.Sprintf("TAG %s TYP %d LEN %d", hex.EncodeToString(com.Tag[:]), com.Typ, com.Length)
}

// Write tag bytes and type byte into the buffer.
func (com TTL) WriteTo(out *bytes.Buffer) {
	out.Write(com.Tag[:])
	out.WriteByte(com.Typ)
}

// TTLV structure. Length of value is sum of item lengths including padding.
type Structure struct {
	TTL
	Items []interface{}
}

// TTLV integer. Length of value is 4. Representation comes with 4 additional bytes of padding.
type Integer struct {
	TTL
	Value int32
}

// TTLV long integer. Length of value is 8.
type LongInteger struct {
	TTL
	Value int64
}

// TTLV enumeration. Length of value is 4. Representation comes with 4 additional bytes of padding.
type Enumeration struct {
	TTL
	Value int32
}

// TTLV date time - seconds since Unix epoch represented as LongInteger. Length of value is 8.
type DateTime struct {
	TTL
	Time time.Time
}

// TTLV text string. Length of value is actual string length, but representation is padded to align with 8 bytes.
type Text struct {
	TTL
	Value string
}

// TTLV byte array. Length of value is actual array length, but representation is padded to align with 8 bytes.
type Bytes struct {
	TTL
	Value []byte
}

// Round input integer upward to be divisible by 8.
func RoundUpTo8(in int) int {
	if in%8 != 0 {
		in += 8 - (in % 8)
	}
	return in
}

// Decode wireshark's hex dump of a network packet into byte array by removing its extra pieces.
func WiresharkDumpToBytes(in string) []byte {
	var bufStr bytes.Buffer
	for _, line := range strings.Split(in, "\n") {
		bufStr.WriteString(strings.Replace(line[7:], " ", "", -1))
	}
	ret, err := hex.DecodeString(bufStr.String())
	if err != nil {
		log.Printf("WiresharkDumpToBytes: failed to decode hex string - %v", err)
		return []byte{}
	}
	return ret
}

// Generate a string that describes an item in very detail. If the item is a structure, the output descends into the child items too.
func DebugTTLVItem(indent int, entity interface{}) string {
	var ret bytes.Buffer
	ret.WriteString(strings.Repeat(" ", indent))
	if entity == nil {
		ret.WriteString("(nil)")
	} else {
		switch t := entity.(type) {
		case Structure:
			ret.WriteString(t.TTL.String())
			ret.WriteRune('\n')
			for _, item := range t.Items {
				ret.WriteString(DebugTTLVItem(indent+4, item))
			}
		case Integer:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case LongInteger:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case DateTime:
			ret.WriteString(fmt.Sprintf("%s - %s", t.TTL.String(), t.Time.Format(time.RFC3339)))
			ret.WriteRune('\n')
		case Enumeration:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case Text:
			ret.WriteString(fmt.Sprintf("%s - %s", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case Bytes:
			ret.WriteString(fmt.Sprintf("%s - %s", t.TTL.String(), hex.EncodeToString(t.Value)))
			ret.WriteRune('\n')
		default:
			ret.WriteString(fmt.Sprintf("(Unknown structure) %+v", t))
			ret.WriteRune('\n')
		}
	}
	return ret.String()
}

// Encode any fixed-size integer into big endian byte array and return.
func EncodeIntBigEndian(someInt interface{}) []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, someInt); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func EncodeAny(thing interface{}) (ret []byte, length int) {
	buf := new(bytes.Buffer)
	switch t := thing.(type) {
	case Structure:
		t.TTL.WriteTo(buf)
		// Collect items while calculating total length
		itemsBuf := new(bytes.Buffer)
		for _, item := range t.Items {
			encodedItem, itemLength := EncodeAny(item)
			length += LenTTL + itemLength
			itemsBuf.Write(encodedItem)
		}
		buf.Write(EncodeIntBigEndian(int32(length)))
		buf.Write(itemsBuf.Bytes())
	case Integer:
		t.TTL.WriteTo(buf)
		// Integer has length of 4
		buf.Write(EncodeIntBigEndian(int32(4)))
		buf.Write(EncodeIntBigEndian(t.Value))
		// An additional 4 bytes of padding not counted against length
		length = 8
		buf.Write([]byte{0, 0, 0, 0})
	case LongInteger:
		t.TTL.WriteTo(buf)
		// LongInteger has length of 8
		length = 8
		buf.Write(EncodeIntBigEndian(int32(8)))
		buf.Write(EncodeIntBigEndian(t.Value))
	case Enumeration:
		t.TTL.WriteTo(buf)
		// Enumeration has length of 4
		buf.Write(EncodeIntBigEndian(int32(4)))
		buf.Write(EncodeIntBigEndian(t.Value))
		// An additional 4 bytes of padding not counted against length
		length = 8
		buf.Write([]byte{0, 0, 0, 0})
	case DateTime:
		t.TTL.WriteTo(buf)
		// DateTime has length of 8
		length = 8
		buf.Write(EncodeIntBigEndian(int32(8)))
		buf.Write(EncodeIntBigEndian(t.Time.Unix()))
	case Text:
		t.TTL.WriteTo(buf)
		// String length is actual length
		buf.Write(EncodeIntBigEndian(int32(len(t.Value))))
		buf.Write([]byte(t.Value))
		// Pad with zero bytes to line up with 8
		length = RoundUpTo8(len(t.Value))
		padding := make([]byte, length-len(t.Value))
		buf.Write(padding)
	case Bytes:
		t.TTL.WriteTo(buf)
		// Bytes length is actual length
		length = len(t.Value)
		buf.Write(EncodeIntBigEndian(int32(len(t.Value))))
		buf.Write(t.Value)
		// Pad with zero bytes to line up with 8
		length = RoundUpTo8(len(t.Value))
		padding := make([]byte, length-len(t.Value))
		buf.Write(padding)
	}
	return buf.Bytes(), length
}

// Decode tag, type, and original value length excluding padding from the first several bytes of input buffer.
func DecodeTTL(in []byte) (tag Tag, typ byte, length int32, err error) {
	if len(in) < LenTTL {
		err = io.EOF
		return
	}
	copy(tag[:], in[:3])
	typ = in[3]
	binary.Read(bytes.NewReader(in[4:8]), binary.BigEndian, &length)
	return
}

// Decode any TTLV item and return.
func DecodeAny(in []byte) (ret interface{}, length int, err error) {
	tag, typ, length32, err := DecodeTTL(in)
	length = int(length32)
	if err == io.EOF {
		return
	} else if err != nil {
		return
	}
	if length <= 0 {
		return nil, length, fmt.Errorf("DecodeAny: length of type %d must be positive, but it is %d.", typ, length)
	}
	common := TTL{Tag: tag, Typ: typ, Length: length}
	in = in[LenTTL:]
	switch typ {
	case TypeEnum:
		// Value length is defined at 4, but representation uses 8 bytes.
		length = 8
		enum := Enumeration{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:4]), binary.BigEndian, &enum.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = enum
	case TypInt:
		// Value length is defined at 4, but representation uses 8 bytes.
		length = 8
		integer := Integer{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:4]), binary.BigEndian, &integer.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = integer
	case TypLong:
		length = 8
		long := LongInteger{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:8]), binary.BigEndian, &long.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = long
	case TypStruct:
		in = in[:length]
		structure := Structure{TTL: common, Items: make([]interface{}, 0, 4)}
		itemIndex := 0
		for {
			// Decode item at current index
			item, itemLength, err := DecodeAny(in)
			if err != nil {
				return nil, length, fmt.Errorf("DecodeAny: failed to decode structure %s's item - %v", common.String(), err)
			}
			structure.Items = append(structure.Items, item)
			// Advance index by the length of decoded TTL plus newly decoded item
			itemIndex = LenTTL + itemLength
			if itemIndex >= len(in) {
				break
			}
			// Continue processing the next item
			in = in[itemIndex:]
		}
		ret = structure
	case TypeText:
		// Length in TTL is true string length, excluding padding.
		ret = Text{TTL: common, Value: string(in[:length])}
		// Value length is true string length, but representation may contain padding to be divisible by 8.
		length = RoundUpTo8(length)
	case TypeBytes:
		// Length in TTL is true string length, excluding padding.
		ret = Bytes{TTL: common, Value: in[:length]}
		// Value length is true string length, but representation may contain padding to be divisible by 8.
		length = RoundUpTo8(length)
	case TypeDateTime:
		length = 8
		var longInt int64
		if err := binary.Read(bytes.NewReader(in[:8]), binary.BigEndian, &longInt); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = DateTime{TTL: common, Time: time.Unix(longInt, 0)}
	default:
		return nil, length, fmt.Errorf("DecodeAny: does not know how to decode %s's type", common.String())
	}
	return
}
