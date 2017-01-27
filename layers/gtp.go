// Copyright 2016 torukita, 2017 Kentaro Ebisawa. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
    "fmt"
	"encoding/binary"
	//"encoding/hex"
    "github.com/google/gopacket"
	//"errors"
)


// GPRS Tunneling Protocol (GTP) is group of protocols used to carry
// control message and user data in mobile networks. (GSM, LTE etc.)
// There are two versions of GTP, GTPv1 and GTP v2, and three types
// such as GTP-C, GTP-U, GTP'(prime).
//
// Type  | Role                    | GTP version | TCP/UDP port 
// ------+-------------------------+-------------+ -------------
// GTP-C | carries control message | GTPv1,GTPv2 | 2123
// GTP-U | carries user data       | GTPv1       | 2152
// GTP'  | carries charging data   | GTPv1,GTPv2 | 3386
//
// Note: Only GTP-U on GTPv1 is currently implemented.
//       GTPv1 Extention header is NOT implemented yet.
//
// GTPv1 Header:
//                      1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Ver |T|R|E|S|N|  Message Type |        Message Length         | 
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Tunnel Endpoint Identifier (TEID)               | 
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Sequence number        | N-PDU Number  |   Next Type   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
// Ver: Vertion. GTPv1(1), GTPv2(2)
//  T : Protocol Type : GTP(1), GTP'(0)
//  R : Reserved (must be 0)
//  E : Extension Header flag : not present (0), present (1)
//  S : Sequence number flag : not present (0), present (1)
//  N : N-PDU Number flag : not present (0), present (1)
// Message Type: The type of GTP message defined in 3GPP TS 29.060 section 7.1
// Message Length: The length in octets of the payload, i.e. the rest of the
//   packet following the mandatory part of the GTP header.(the first 8 octets)
//   The Sequence Number, the N-PDU Number or any Extension headers shall be
//   considered to be part of the payload, i.e. included in the length count.
// Tunnel Endpoint Identifier (TEID): an endpoint ID :-)
// Sequence number: optional. exists if any of E, S, N bits are on.
// N-PDU Number: optional. exists if any of E, S, N bits are on.
// Next Extension Header Type: optional. exists if any of E, S, N bits are on.
//
// References:
// * https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol
// * #29.281 GPRS Tunnelling Protocol User Plane (GTPv1-U)
//   https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1699

// GTPv1 is the layer for GTPv1 headers.
// TODO: We should have GTP header just to identify version and pass to GTPv1 or v2.
type GTPv1 struct {
	BaseLayer
	// Header Fields
	Version                        uint8   // 3bit
	ProtocolType                   bool    // GTP(1:true), GTP'(0:false)
	Reserved                       bool    // always 0:false
	ExtentionHeaderFlag            bool
	SequenceNumberFlag             bool
	NPDUNumberFlag                 bool
	MessageType                    uint8   // 8bit
	MessageLength                  uint16  // 16bit
	TEID                           uint32  // 32bit
	SequenceNumber                 uint16  // 16bit
	NPDUNumber                     uint8   // 8bit
    NextExtentionHeaderType        uint8   // 8bit
	//ExtentionHeader                []*GtpExtentionHeader
}

// LayerType returns gopacket.LayerTypeGTP
func (g *GTPv1) LayerType() gopacket.LayerType { return LayerTypeGTP }
//TODO: Use GTP as genric layer to identify version and change to LayerTypeGTPv1.
//func (g *GTPv1) LayerType() gopacket.LayerType { return LayerTypeGTPv1 }

func (g *GTPv1) CanDecode() gopacket.LayerClass {
	//TODO: return LayerTypeGTPv1
	return LayerTypeGTP
}

func (g *GTPv1) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("GTP packet too short")
	}
	// Decode mandatory header fields (8 bytes)
	g.Version = (data[0] >>5) & 0x07
	g.ProtocolType = data[0]&0x10 != 0 // <<4
	g.Reserved     = data[0]&0x08 != 0 // <<3
	g.ExtentionHeaderFlag = data[0]&0x04 != 0 // << 2
	g.SequenceNumberFlag  = data[0]&0x02 != 0 // << 1
	g.NPDUNumberFlag = data[0]&0x01 != 0 // <<0
	g.MessageType = uint8(data[1])
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])
	g.BaseLayer = BaseLayer{Contents: data[:len(data) - int(g.MessageLength)]}
	g.TEID = binary.BigEndian.Uint32(data[4:8])

	// Decode optional header fields
	if g.ExtentionHeaderFlag || g.SequenceNumberFlag || g.NPDUNumberFlag {
		g.SequenceNumber = binary.BigEndian.Uint16(data[8:10])
		g.NPDUNumber = uint8(data[10])
		g.NextExtentionHeaderType = uint8(data[11])
		g.Payload = data[12:]
	} else {
		g.Payload = data[8:]
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (g *GTPv1) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	//fmt.Println("DEBUG: entering SerializeTo")
	// Validate Fields
	// Validate Message Length
	// err := g.ValidateMessageLength()
	// if err != nil { return err }
	if g.ExtentionHeaderFlag || g.SequenceNumberFlag || g.NPDUNumberFlag {
		if g.MessageLength < 4 {
			return fmt.Errorf("GTP: Message Length too short %d", g.MessageLength)
		}
	} else {
		if g.MessageLength != 0 { // only mandatory fields exist
			return fmt.Errorf("GTP: Message Length should be 0. No optional fields.")
		}
	}
	if g.Version != 1 { return fmt.Errorf("GTP: Version should be 1.") }
	if g.Reserved { return fmt.Errorf("GTP: Reserved is always 0.") }

	///fmt.Println("DEBUG: Validatoin completed.")

	// TODO: support options.FixLengths = true
	buf, err := b.PrependBytes(int(g.MessageLength+8))
	if err != nil { return err }
	//fmt.Println("DEBUG: PrependBytes Success.", g.MessageLength+8)
	//fmt.Println( "buf:", hex.EncodeToString(buf))

	// Set fields
	// set version first to fill any potentially dirty memory in the first byte to 0.
	buf[0] = g.Version << 5
	if g.ProtocolType { buf[0] |= 0x10 } // <<4
	if g.ExtentionHeaderFlag { buf[0] |= 0x04 } // <<2
	if g.SequenceNumberFlag { buf[0] |= 0x02 } // <<1
	if g.NPDUNumberFlag { buf[0] |= 0x01 } //0
	buf[1] = g.MessageType
	binary.BigEndian.PutUint16(buf[2:], uint16(g.MessageLength))
	binary.BigEndian.PutUint32(buf[4:], uint32(g.TEID))
	// set optional fields. buf size is 12+ if any of the Flags was set.
	if g.SequenceNumberFlag {
		binary.BigEndian.PutUint16(buf[8:], uint16(g.SequenceNumber))
	}
	if g.NPDUNumberFlag {
		buf[10] = g.NPDUNumber
	}
	if g.ExtentionHeaderFlag {
		buf[11] = g.NextExtentionHeaderType
	}
	return nil
}

func (g *GTPv1) NextLayerType() gopacket.LayerType {
	//return gopacket.LayerTypePayload
	return LayerTypeIPv4
}

func (g *GTPv1) LayerPayload() []byte {
    return g.Payload
}

//func decodeGTPv1(data []byte, p gopacket.PacketBuilder) error {
func decodeGTP(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv1{}
	return decodingLayerDecoder(gtp, data, p)
}
