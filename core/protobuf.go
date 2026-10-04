package core

import (
	"errors"
	"fmt"
)

// ---- 最小 protobuf wire format 编解码 ----
//
// 仅覆盖 geosite.dat / geoip.dat 用到的 wire 类型：
//   0 = varint，2 = length-delimited（bytes / string / 嵌套消息）。
// 这两个文件是 v2ray-core routercommon 的稳定格式，手写实现可避免引入重型 protobuf 依赖。

var errProtoEnd = errors.New("protobuf: 数据意外结束")

// appendVarint 追加一个 base128 varint。
func appendVarint(b []byte, n uint64) []byte {
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	return append(b, byte(n))
}

func appendTag(b []byte, field, wire int) []byte {
	return appendVarint(b, uint64(field)<<3|uint64(wire))
}

func appendBytesField(b []byte, field int, v []byte) []byte {
	b = appendTag(b, field, 2)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendStringField(b []byte, field int, s string) []byte {
	return appendBytesField(b, field, []byte(s))
}

func appendVarintField(b []byte, field int, n uint64) []byte {
	b = appendTag(b, field, 0)
	return appendVarint(b, n)
}

// pbuf 是前进式解码器。
type pbuf struct {
	b   []byte
	pos int
}

func (p *pbuf) more() bool { return p.pos < len(p.b) }

func (p *pbuf) readVarint() (uint64, error) {
	var n uint64
	var shift uint
	for {
		if p.pos >= len(p.b) {
			return 0, errProtoEnd
		}
		c := p.b[p.pos]
		p.pos++
		if shift >= 64 {
			return 0, errors.New("protobuf: varint 过长")
		}
		n |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return n, nil
		}
		shift += 7
	}
}

// readField 读取下一个字段的 field 号与 wire 类型；数据读完时返回 field == -1。
func (p *pbuf) readField() (field, wire int, err error) {
	if !p.more() {
		return -1, 0, nil
	}
	tag, err := p.readVarint()
	if err != nil {
		return 0, 0, err
	}
	if tag == 0 {
		return 0, 0, errors.New("protobuf: 非法的 0 字段号")
	}
	return int(tag >> 3), int(tag & 0x7), nil
}

// readBytes 读取 length-delimited 字段内容。
func (p *pbuf) readBytes() ([]byte, error) {
	n, err := p.readVarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(p.b)-p.pos) {
		return nil, errProtoEnd
	}
	v := p.b[p.pos : p.pos+int(n)]
	p.pos += int(n)
	return v, nil
}

// skip 跳过任意 wire 类型的字段（用于容忍未知字段）。
func (p *pbuf) skip(wire int) error {
	switch wire {
	case 0:
		_, err := p.readVarint()
		return err
	case 2:
		_, err := p.readBytes()
		return err
	case 1: // 64-bit fixed
		if p.pos+8 > len(p.b) {
			return errProtoEnd
		}
		p.pos += 8
		return nil
	case 5: // 32-bit fixed
		if p.pos+4 > len(p.b) {
			return errProtoEnd
		}
		p.pos += 4
		return nil
	default:
		return fmt.Errorf("protobuf: 不支持的 wire 类型 %d", wire)
	}
}
