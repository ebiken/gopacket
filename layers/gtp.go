// Copyright 2016 torukita, 2017 Kentaro Ebisawa. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
    "fmt"
	"encoding/binary"
    "github.com/google/gopacket"
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
//   packet following the mandatory part of the GTP header (the first 8 octets)
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
	ProtocolType                   uint8   // 1bit
	Reserved                       uint8   // 1bit
	ExtentionHeaderFlag            uint8   // 1bit 
	SequenceNumberFlag             uint8   // 1bit
	NPDUNumberFlag                 uint8   // 1bit
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
	g.Version = (data[0] >>5) & 0x07
	g.ProtocolType = (data[0] >> 4) & 0x01
	g.Reserved = 0
	g.ExtentionHeaderFlag = (data[0] >> 2) & 0x01
	g.SequenceNumberFlag = (data[0] >> 1) & 0x01
	g.NPDUNumberFlag = data[0] & 0x01
	g.MessageType = uint8(data[1])
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])
	// fmt.Printf("MessageLength=%d\n", g.MessageLength)
	g.BaseLayer = BaseLayer{Contents: data[:len(data) - int(g.MessageLength)]}
	g.TEID = binary.BigEndian.Uint32(data[4:8])

	if g.ExtentionHeaderFlag >0 || g.SequenceNumberFlag >0 || g.NPDUNumberFlag > 0 {
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
//func (g *GTPv1) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
// TODO: 
//}

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
