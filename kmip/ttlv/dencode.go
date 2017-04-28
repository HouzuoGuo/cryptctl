package ttlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"strings"
	"time"
)

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
		if line == "" {
			continue
		}
		bufStr.WriteString(strings.Replace(line[7:], " ", "", -1))
	}
	ret, err := hex.DecodeString(bufStr.String())
	if err != nil {
		log.Printf("WiresharkDumpToBytes: failed to decode hex string - %v", err)
		return []byte{}
	}
	return ret
}

// Generate a string that describes an item (pointer) in very detail. If the item is a structure, the output descends into the child items too.
func DebugTTLVItem(indent int, entity interface{}) string {
	var ret bytes.Buffer
	ret.WriteString(strings.Repeat(" ", indent))
	if entity == nil {
		ret.WriteString("(nil)")
	} else {
		switch t := entity.(type) {
		case *Structure:
			ret.WriteString(t.TTL.String())
			ret.WriteRune('\n')
			for _, item := range t.Items {
				ret.WriteString(DebugTTLVItem(indent+4, item))
			}
		case *Integer:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case *LongInteger:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case *DateTime:
			ret.WriteString(fmt.Sprintf("%s - %s", t.TTL.String(), t.Time.Format(time.RFC3339)))
			ret.WriteRune('\n')
		case *Enumeration:
			ret.WriteString(fmt.Sprintf("%s - %d", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case *Text:
			ret.WriteString(fmt.Sprintf("%s - %s", t.TTL.String(), t.Value))
			ret.WriteRune('\n')
		case *Bytes:
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

// Encode any TTLV item. Input must be pointer to item.
func EncodeAny(thing interface{}) (ret []byte) {
	buf := new(bytes.Buffer)
	switch t := thing.(type) {
	case *Structure:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		for _, item := range t.Items {
			buf.Write(EncodeAny(item))
		}
	case *Integer:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		// Integer has length of 4
		buf.Write(EncodeIntBigEndian(t.Value))
		// An additional 4 bytes of padding not counted against length
		buf.Write([]byte{0, 0, 0, 0})
	case *LongInteger:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		// LongInteger has length of 8
		buf.Write(EncodeIntBigEndian(t.Value))
	case *Enumeration:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		// Enumeration has length of 4
		buf.Write(EncodeIntBigEndian(t.Value))
		// An additional 4 bytes of padding not counted against length
		buf.Write([]byte{0, 0, 0, 0})
	case *DateTime:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		// DateTime has length of 8
		buf.Write(EncodeIntBigEndian(t.Time.Unix()))
	case *Text:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		buf.Write([]byte(t.Value))
		// Pad with zero bytes to line up with 8
		padding := make([]byte, RoundUpTo8(len(t.Value))-len(t.Value))
		buf.Write(padding)
	case *Bytes:
		t.TTL.WriteTTTo(buf)
		buf.Write(EncodeIntBigEndian(int32(t.GetLength())))
		buf.Write(t.Value)
		// Pad with zero bytes to line up with 8
		padding := make([]byte, RoundUpTo8(len(t.Value))-len(t.Value))
		buf.Write(padding)
	}
	return buf.Bytes()
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

// Decode any TTLV item and return pointer to item.
func DecodeAny(in []byte) (ret Item, length int, err error) {
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
		enum := &Enumeration{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:4]), binary.BigEndian, &enum.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = enum
	case TypInt:
		// Value length is defined at 4, but representation uses 8 bytes.
		length = 8
		integer := &Integer{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:4]), binary.BigEndian, &integer.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = integer
	case TypLong:
		length = 8
		long := &LongInteger{TTL: common}
		if err := binary.Read(bytes.NewReader(in[:8]), binary.BigEndian, &long.Value); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = long
	case TypStruct:
		in = in[:length]
		structure := &Structure{TTL: common, Items: make([]interface{}, 0, 4)}
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
		ret = &Text{TTL: common, Value: string(in[:length])}
		// Value length is true string length, but representation may contain padding to be divisible by 8.
		length = RoundUpTo8(length)
	case TypeBytes:
		// Length in TTL is true string length, excluding padding.
		ret = &Bytes{TTL: common, Value: in[:length]}
		// Value length is true string length, but representation may contain padding to be divisible by 8.
		length = RoundUpTo8(length)
	case TypeDateTime:
		length = 8
		var longInt int64
		if err := binary.Read(bytes.NewReader(in[:8]), binary.BigEndian, &longInt); err != nil {
			return nil, length, fmt.Errorf("DecodeAny: failed to decode %s's value - %v", common.String(), err)
		}
		ret = &DateTime{TTL: common, Time: time.Unix(longInt, 0)}
	default:
		return nil, length, fmt.Errorf("DecodeAny: does not know how to decode %s's type", common.String())
	}
	return
}

// Copy value of a primitive TTLV item from src to dest. Both src and dest are pointers.
func CopyValue(dest, src Item) error {
	if src == nil {
		return errors.New("CopyValue: source value may not be nil")
	}
	if dest == nil {
		return errors.New("CopyValue: destination value may not be nil")
	}
	typeErr := fmt.Errorf("CopyValue: was expecting destination to be of type %s, but it is %s.", reflect.TypeOf(src).String(), reflect.TypeOf(dest).String())
	switch t := src.(type) {
	case *Integer:
		if tDest, yes := dest.(*Integer); yes {
			tDest.Value = t.Value
		} else {
			return typeErr
		}
	case *LongInteger:
		if tDest, yes := dest.(*LongInteger); yes {
			tDest.Value = t.Value
		} else {
			return typeErr
		}
	case *Enumeration:
		if tDest, yes := dest.(*Enumeration); yes {
			tDest.Value = t.Value
		} else {
			return typeErr
		}
	case *DateTime:
		if tDest, yes := dest.(*DateTime); yes {
			tDest.Time = t.Time
		} else {
			return typeErr
		}
	case *Text:
		if tDest, yes := dest.(*Text); yes {
			tDest.Value = t.Value
		} else {
			return typeErr
		}
	case *Bytes:
		if tDest, yes := dest.(*Bytes); yes {
			tDest.Value = make([]byte, len(t.Value))
			copy(tDest.Value, t.Value)
		} else {
			return typeErr
		}
	default:
		return fmt.Errorf("CopyValue: unknown source value type %s", reflect.TypeOf(src).String())
	}
	return nil
}
