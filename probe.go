package portmap

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type ProbeResult struct {
	PCP  bool
	PMP  bool
	UPnP bool
}

// Probe returns a summary of which port mapping services are
// available on the network.
//
// If a probe has run recently and there haven't been any network changes since,
// the returned result might be server from the Client's cache, without
// sending any network traffic.
func (c *Client) Probe(ctx context.Context) (res ProbeResult, err error) {
	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		return res, ErrGatewayRange
	}
	defer func() {
		if err == nil {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.lastProbe = time.Now()
		}
	}()

	uc, err := c.listenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		c.logf("ProbePCP: %v", err)
		return res, err
	}
	defer uc.Close()
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	defer closeCloserOnContextDone(ctx, uc)()

	pxpAddr := netip.AddrPortFrom(gw, c.pxpPort())
	upnpAddr := netip.AddrPortFrom(gw, c.upnpPort())
	upnpMulticastAddr := netip.AddrPortFrom(netaddr.IPv4(239, 255, 255, 250), c.upnpPort())

	// Don't send probes to services that we recently learned (for
	// the same gw/myIP) are available. See
	// https://github.com/tailscale/tailscale/issues/1001
	if c.sawPMPRecently() {
		res.PMP = true
	} else if !c.debug.DisablePMP {
		uc.WriteToUDPAddrPort(pmpReqExternalAddrPacket, pxpAddr)
	}
	if c.sawPCPRecently() {
		res.PCP = true
	} else if !c.debug.DisablePCP {
		uc.WriteToUDPAddrPort(pcpAnnounceRequest(myIP), pxpAddr)
	}
	if c.sawUPnPRecently() {
		res.UPnP = true
	} else if !c.debug.DisableUPnP {
		// Strictly speaking, you discover UPnP services by sending an
		// SSDP query (which uPnPPacket is) to udp/1900 on the SSDP
		// multicast address, and then get a flood of responses back
		// from everything on your network.
		//
		// Empirically, many home routers also respond to SSDP queries
		// directed at udp/1900 on their LAN unicast IP
		// (e.g. 192.168.1.1). This is handy because it means we can
		// probe the router directly and likely get a reply. However,
		// the specs do not _require_ UPnP devices to respond to
		// unicast SSDP queries, so some conformant UPnP
		// implementations only respond to multicast queries.
		//
		// In theory, we could send just the multicast query and get
		// all compliant devices to respond. However, we instead send
		// to both a unicast and a multicast addresses, for a couple
		// of reasons:
		//
		// First, some LANs and OSes have broken multicast in one way
		// or another, so it's possible for the multicast query to be
		// lost while the unicast query gets through. But we still
		// have to send the multicast query to also get a response
		// from strict-UPnP devices on multicast-working networks.
		//
		// Second, SSDP's packet dynamics are a bit weird: you send
		// the SSDP query from your unicast IP to the SSDP multicast
		// IP, but responses are from the UPnP devices's _unicast_ IP
		// to your unicast IP. This can confuse some less-intelligent
		// stateful host firewalls, who might block the responses. To
		// work around this, we send the unicast query first, to teach
		// the firewall to expect a unicast response from the router,
		// and then send our multicast query. That way, even if the
		// device doesn't respond to the unicast query, we've set the
		// stage for the host firewall to accept the response to the
		// multicast query.
		//
		// See https://github.com/tailscale/tailscale/issues/3197 for
		// an example of a device that strictly implements UPnP, and
		// only responds to multicast queries.
		//
		// Then we send a discovery packet looking for
		// urn:schemas-upnp-org:device:InternetGatewayDevice:1 specifically, not
		// just ssdp:all, because there appear to be devices which only send
		// their first descriptor (like urn:schemas-wifialliance-org:device:WFADevice:1)
		// in response to ssdp:all. https://github.com/tailscale/tailscale/issues/3557
		uc.WriteToUDPAddrPort(uPnPPacket, upnpAddr)
		uc.WriteToUDPAddrPort(uPnPPacket, upnpMulticastAddr)
		uc.WriteToUDPAddrPort(uPnPIGDPacket, upnpMulticastAddr)
	}

	buf := make([]byte, 1500)
	pcpHeard := false // true when we get any PCP response
	for {
		if pcpHeard && res.PMP && res.UPnP {
			// Nothing more to discover.
			return res, nil
		}
		n, addr, err := uc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				err = nil
			}
			return res, err
		}
		ip, ok := netip.AddrFromSlice(addr.(*net.UDPAddr).IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()

		handleUPnPResponse := func() {
			if ip != gw {
				// https://github.com/tailscale/tailscale/issues/5502
				c.logf("UPnP discovery response from %v, but gateway IP is %v", ip, gw)
			}
			meta, err := parseUPnPDiscoResponse(buf[:n])
			if err != nil {
				c.logf("unrecognized UPnP discovery response; ignoring: %v", err)
				return
			}
			c.logf("[v1] UPnP reply %+v, %q", meta, buf[:n])
			res.UPnP = true
			c.mu.Lock()
			c.uPnPSawTime = time.Now()
			if c.uPnPMeta != meta {
				c.logf("UPnP meta changed: %+v", meta)
				c.uPnPMeta = meta
			}
			c.mu.Unlock()
		}

		port := uint16(addr.(*net.UDPAddr).Port)
		switch port {
		case c.upnpPort():
			if mem.Contains(mem.B(buf[:n]), mem.S(":InternetGatewayDevice:")) {
				handleUPnPResponse()
			}

		default:
			// https://github.com/tailscale/tailscale/issues/7377
			if mem.Contains(mem.B(buf[:n]), mem.S(":InternetGatewayDevice:")) {
				c.logf("UPnP discovery response from non-UPnP port %d", port)
				handleUPnPResponse()
			}

		case c.pxpPort(): // same value for PMP and PCP
			if pres, ok := parsePCPResponse(buf[:n]); ok {
				if pres.OpCode == pcpOpReply|pcpOpAnnounce {
					pcpHeard = true
					c.mu.Lock()
					c.pcpSawTime = time.Now()
					c.mu.Unlock()
					switch pres.ResultCode {
					case pcpCodeOK:
						c.logf("[v1] Got PCP response: epoch: %v", pres.Epoch)
						res.PCP = true
						continue
					case pcpCodeNotAuthorized:
						// A PCP service is running, but refuses to
						// provide port mapping services.
						res.PCP = false
						continue
					case pcpCodeAddressMismatch:
						// A PCP service is running, but it is behind a NAT, so it can't help us.
						res.PCP = false
						continue
					default:
						// Fall through to unexpected log line.
					}
				}
				c.logf("unexpected PCP probe response: %+v", pres)
			}
			if pres, ok := parsePMPResponse(buf[:n]); ok {
				if pres.OpCode != pmpOpReply|pmpOpMapPublicAddr {
					c.logf("unexpected PMP probe response opcode: %+v", pres)
					continue
				}
				switch pres.ResultCode {
				case pmpCodeOK:
					c.logf("[v1] Got PMP response; IP: %v, epoch: %v", pres.PublicAddr, pres.SecondsSinceEpoch)
					res.PMP = true
					c.mu.Lock()
					c.pmpPubIP = pres.PublicAddr
					c.pmpPubIPTime = time.Now()
					c.pmpLastEpoch = pres.SecondsSinceEpoch
					c.mu.Unlock()
					continue
				case pmpCodeNotAuthorized:
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				case pmpCodeNetworkFailure:
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				case pmpCodeOutOfResources:
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				}
				c.logf("unexpected PMP probe response: %+v", pres)
			}
		}
	}
}
