//go:build !js

// Package pmp implements RFC6886, the NAT Port Mapping Protocol (NAT-PMP)
// See: https://datatracker.ietf.org/doc/html/rfc6886
package pmp

import (
	"encoding/binary"
	"net/netip"
)

type resultCode uint16

// NAT-PMP constants.
const (
	defaultPort       = 5351
	mapLifetimeSec    = 7200 // RFC recommended 2 hour map duration
	mapLifetimeDelete = 0    // 0 second lifetime deletes

	version = 0

	opMapPublicAddr = 0
	opMapUDP        = 1
	opReply         = 0x80 // OR'd into request's op code on response

	codeOK                 resultCode = 0
	codeUnsupportedVersion resultCode = 1
	codeNotAuthorized      resultCode = 2 // "e.g., box supports mapping, but user has turned feature off"
	codeNetworkFailure     resultCode = 3 // "e.g., NAT box itself has not obtained a DHCP lease"
	codeOutOfResources     resultCode = 4
	codeUnsupportedOpcode  resultCode = 5
)

type response struct {
	OpCode            uint8
	ResultCode        resultCode
	SecondsSinceEpoch uint32

	// For Map ops:
	MappingValidSeconds uint32
	InternalPort        uint16
	ExternalPort        uint16

	// For public addr ops:
	PublicAddr netip.Addr
}

func parseResponse(pkt []byte) (res response, ok bool) {
	if len(pkt) < 12 {
		return
	}
	ver := pkt[0]
	if ver != 0 {
		return
	}
	res.OpCode = pkt[1]
	res.ResultCode = resultCode(binary.BigEndian.Uint16(pkt[2:]))
	res.SecondsSinceEpoch = binary.BigEndian.Uint32(pkt[4:])

	if res.OpCode == opReply|opMapUDP {
		if len(pkt) != 16 {
			return res, false
		}
		res.InternalPort = binary.BigEndian.Uint16(pkt[8:])
		res.ExternalPort = binary.BigEndian.Uint16(pkt[10:])
		res.MappingValidSeconds = binary.BigEndian.Uint32(pkt[12:])
	}

	if res.OpCode == opReply|opMapPublicAddr {
		if len(pkt) != 12 {
			return res, false
		}
		res.PublicAddr = netaddr.IPv4(pkt[8], pkt[9], pkt[10], pkt[11])
	}

	return res, true
}

func buildRequestMappingPacket(localPort, prevPort uint16, lifetimeSec uint32) (pkt []byte) {
	pkt = make([]byte, 12)

	pkt[1] = opMapUDP
	binary.BigEndian.PutUint16(pkt[4:], localPort)
	binary.BigEndian.PutUint16(pkt[6:], prevPort)
	binary.BigEndian.PutUint32(pkt[8:], lifetimeSec)

	return pkt
}
