//go:build !js

// Package pcp implements RFC6887, the Port Control Protocol (PCP)
// See: https://datatracker.ietf.org/doc/html/rfc6887
package pcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// See: https://datatracker.ietf.org/doc/html/rfc6887#section-7.4
type resultCode = uint8

const (
	// Success.
	codeSuccess resultCode = iota

	// The version number at the start of the PCP Request
	// header is not recognized by this PCP server.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeUnsupportedVersion

	// The requested operation is disabled for this PCP
	// client, or the PCP client requested an operation that cannot be
	// fulfilled by the PCP server's security policy.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeNotAuthorized

	// The request could not be successfully parsed.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeMalformedRequest

	// Unsupported Opcode.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeUnsupportedOpCode

	// Unsupported option.
	// This error only occurs if the option is in the mandatory-to-process range.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeUnsupportedOption

	// Malformed option (e.g., appears too many times, invalid length).
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeMalformedOption

	// The PCP server or the device it controls is experiencing
	// a network failure of some sort (e.g., has not yet obtained an external IP address).
	// This is a short lifetime error.
	// This is specified by RFC6887.
	codeNetworkFailure

	// Request is well-formed and valid, but the server has
	// insufficient resources to complete the requested operation at this
	// time.  For example, the NAT device cannot create more mappings at
	// this time, is short of CPU cycles or memory, or is unable to
	// handle the request due to some other temporary condition.  The
	// same request may succeed in the future.  This is a system-wide
	// error, different from USER_EX_QUOTA.  This can be used as a catch-
	// all error, should no other error message be suitable.
	// This is a short lifetime error.
	// This is specified by RFC6887.
	codeNoResources

	// Unsupported transport protocol
	// e.g., SCTP in a NAT that handles only UDP and TCP.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeUnsupportedProtocol

	// This attempt to create a new mapping would exceed
	// this subscriber's port quota.
	// This is a short lifetime error.
	// This is specified by RFC6887.
	codeUserExceededQuota

	// The suggested external port and/or
	// external address cannot be provided.
	// This error MUST only be returned for:
	//  *  MAP requests that included the PREFER_FAILURE option
	//     (normal MAP requests will return an available external port)
	//  *  MAP requests for the SCTP protocol (PREFER_FAILURE is implied)
	//  *  PEER requests
	//
	// See Section 13.2 for details of the PREFER_FAILURE Option.  The
	// error lifetime depends on the reason for the failure.
	// This is specified by RFC6887.
	codeCannotProvideExternal

	// The source IP address of the request packet does
	// not match the contents of the PCP Client's IP Address field, due
	// to an unexpected NAT on the path between the PCP client and the
	// PCP-controlled NAT or firewall.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeAddressMismatch

	// The PCP server was not able to create the filters in this request.
	// This result code MUST only be returned if the MAP request contained
	// the FILTER option.
	// This is a long lifetime error.
	// This is specified by RFC6887.
	codeExcessiveRemotePeers

	// The client includes this PCP result code in its request
	// to the server for authentication.
	// This is specified by RFC7652.
	codeInitiation

	// This error response is sent to the client
	// if EAP authentication is required.
	// This is specified by RFC7652.
	codeAuthnRequired

	// This error response is sent to the client
	// if EAP authentication failed.
	// This is specified by RFC7652.
	codeAuthnFailed

	// This success response is sent to the client
	// if EAP authentication succeeded.
	// This is specified by RFC7652.
	codeAuthnSucceeded

	// This error response is sent to the client
	// if EAP authentication succeeded but authorization failed.
	// This is specified by RFC7652.
	codeAuthzFailed

	// This PCP result code indicates to the partner
	// that the PA session must be terminated.
	// This is specified by RFC7652.
	codeSessionTerminated

	// This error response is sent from the PCP server if there
	// is no known PA session associated with the Session ID sent
	// in the PA request or common PCP request from the PCP client.
	// This is specified by RFC7652.
	codeUnknownSessionID

	// This PCP result code indicates to the client that the
	// server detected a downgrade attack.
	// This is specified by RFC7652.
	codeDowngradeAttackDetected

	// The server indicates to the client that the PA message
	// contains an EAP request.
	// This is specified by RFC7652.
	codeAuthnRequest

	// The client indicates to the server that the PA message
	// contains an EAP response.
	// This is specified by RFC7652.
	codeAuthnReply

	// The provided identifier in a THIRD_PARTY_ID option
	// is unknown/unavailable to the PCP server.
	// This is a long lifetime error.
	// This is specified by RFC7843.
	codeUnknownThirdPartyID

	// This error occurs if both THIRD_PARTY and THIRD_PARTY_ID
	// options are expected in a request but one option is missing.
	// This is a long lifetime error.
	// This is specified by RFC7843.
	codeMissingThirdPartyOption

	// The received option length is not supported.
	// This is a long lifetime error.
	// This is specified by RFC7843.
	codeUnsupportedThirdPartyIDLength
)

type opCode = uint8

const (
	// See: https://datatracker.ietf.org/doc/html/rfc6887#section-14.1
	opAnnounce opCode = iota

	// See: https://datatracker.ietf.org/doc/html/rfc6887#section-11
	opMap

	// See: https://datatracker.ietf.org/doc/html/rfc6887#section-12
	opPeer

	// See: https://datatracker.ietf.org/doc/html/rfc7652#section-5
	opAuthentication

	opReply opCode = 0x80 // OR'd into request's op code on response
)

type option = uint8

const (
	// This is specified by RFC6887.
	optionReserved option = 0

	// Indicates the MAP or PEER request is for a host other than the host sending the PCP Option.
	// May appear in response only if it appeared in the associated request.
	optionThirdParty option = 1

	// Indicates that the PCP server should not create an alternative mapping if the suggested external port and address cannot be mapped.
	// May appear in response only if it appeared in the associated request.
	// This is specified by RFC6887.
	optionPreferFailure option = 2

	// Specifies a filter for incoming packets.
	// May appear in response only if it appeared in the associated request.
	// As many as fit within maximum PCP message size.
	// This is specified by RFC6887.
	optionFilter option = 3

	// See Section 5.3 of [RFC7652].
	// This is specified by RFC7652.
	optionNonce option = 4

	// See Section 5.4 of [RFC7652].
	// This is specified by RFC7652.
	optionAuthnTag option = 5

	// See Section 5.5 of [RFC7652].
	// This is specified by RFC7652.
	optionPAAuthnTag option = 6

	// See Section 5.6 of [RFC7652].
	// This is specified by RFC7652.
	optionEAPPayload option = 7

	// See Section 5.7 of [RFC7652].
	// This is specified by RFC7652.
	optionPRF option = 8

	// See Section 5.8 of [RFC7652].
	// This is specified by RFC7652.
	optionMACAlg option = 9

	// Section 5.9 of [RFC7652].
	// This is specified by RFC7652.
	optionSessionLifetime option = 10

	// See Section 5.10 of [RFC7652].
	// This is specified by RFC7652.
	optionReceivedPAK option = 11

	// See Section 5.11 of [RFC7652].
	// This is specified by RFC7652.
	optionIDIndicator option = 12

	// Together with the THIRD_PARTY option, the THIRD_PARTY_ID option identifies a
	// third party for which a request for an external IP address and port is made.
	// May appear in response only if it appeared in the associated request.
	// This is specified by RFC7843.
	optionThirdPartyID option = 13

	// Used to associate a text description with a mapping.
	// May appear in response only if it appeared in the associated request.
	// This is specified by RFC7220.
	optionDescription option = 128

	// Learn the prefix used by the NAT64 to build IPv4-converted IPv6 addresses.
	// This is used by a host for local address synthesis (e.g., when an IPv4 address is present in referrals).
	// As many as fit within the maximum PCP message size for a response.
	// This is specified by RFC7225.
	optionPrefix64 option = 129

	// To map sets of ports.
	// This is specified by RFC7753.
	optionPort_set option = 130

	// Indicate if an entry needs to be check-pointed.
	// This is specified by RFC7767.
	optionCheckpoint_required option = 192
)

// PCP constants
const (
	version = 2

	// See: https://datatracker.ietf.org/doc/html/rfc6887#section-19.1
	defaultPort = 5351

	// See: https://datatracker.ietf.org/doc/html/rfc6887#section-15
	mapLifetimeSec = 7200 // TODO does the RFC recommend anything? This is taken from PMP.

	udpMapping = 17 // portmap UDP
	tcpMapping = 6  // portmap TCP
)

// buildPCPRequestMappingPacket generates a PCP packet with a MAP opcode.
// To create a packet which deletes a mapping, lifetimeSec should be set to 0.
// If prevPort is not known, it should be set to 0.
// If prevExternalIP is not known, it should be set to 0.0.0.0.
func buildRequestMappingPacket(
	myIP netip.Addr,
	localPort, prevPort uint16,
	lifetimeSec uint32,
	prevExternalIP netip.Addr,
) (pkt []byte) {
	// 24 byte common PCP header + 36 bytes of MAP-specific fields
	pkt = make([]byte, 24+36)
	pkt[0] = version
	pkt[1] = opMap

	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSec)
	myIP16 := myIP.As16()
	copy(pkt[8:24], myIP16[:])

	mapOp := pkt[24:]
	rand.Read(mapOp[:12]) // 96 bit mapping nonce

	// TODO: should this be a UDP mapping? It looks like it supports "all protocols" with 0, but
	// also doesn't support a local port then.
	mapOp[12] = udpMapping
	binary.BigEndian.PutUint16(mapOp[16:18], localPort)
	binary.BigEndian.PutUint16(mapOp[18:20], prevPort)

	prevExternalIP16 := prevExternalIP.As16()
	copy(mapOp[20:], prevExternalIP16[:])

	return pkt
}

// parsePCPMapResponse parses resp into a partially populated pcpMapping.
// In particular, its Client is not populated.
func parseMapResponse(resp []byte) (*pcpMapping, error) {
	if len(resp) < 60 {
		return nil, fmt.Errorf("Does not appear to be PCP MAP response")
	}

	res, ok := parseResponse(resp[:24])
	if !ok {
		return nil, fmt.Errorf("Invalid PCP common header")
	}

	if res.ResultCode == codeNotAuthorized {
		return nil, fmt.Errorf("PCP is implemented but not enabled in the router")
	}

	if res.ResultCode != codeSuccess {
		return nil, fmt.Errorf("PCP response not ok, code %d", res.ResultCode)
	}

	// TODO: don't ignore the nonce and make sure it's the same?
	externalPort := binary.BigEndian.Uint16(resp[42:44])

	externalIPBytes := [16]byte{}
	copy(externalIPBytes[:], resp[44:])

	externalIP := netip.AddrFrom16(externalIPBytes).Unmap()

	external := netip.AddrPortFrom(externalIP, externalPort)

	lifetime := time.Second * time.Duration(res.Lifetime)
	now := time.Now()
	mapping := &pcpMapping{
		external:   external,
		renewAfter: now.Add(lifetime / 2),
		goodUntil:  now.Add(lifetime),
	}

	return mapping, nil
}

// announceRequest generates a PCP packet with an ANNOUNCE opcode.
// See: https://tools.ietf.org/html/rfc6887#section-7.1
func announceRequest(myIP netip.Addr) []byte {
	pkt := make([]byte, 24)
	pkt[0] = version
	pkt[1] = opAnnounce

	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])

	return pkt
}

type response struct {
	OpCode     uint8
	ResultCode resultCode
	Lifetime   uint32
	Epoch      uint32
}

func parseResponse(b []byte) (res response, ok bool) {
	if len(b) < 24 || b[0] != version {
		return
	}

	res.OpCode = b[1]
	res.ResultCode = resultCode(b[3])
	res.Lifetime = binary.BigEndian.Uint32(b[4:])
	res.Epoch = binary.BigEndian.Uint32(b[8:])

	return res, true
}
