package igd

// uPnPPacket is the UPnP UDP discovery packet's request body.
var uPnPPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: ssdp:all\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

// Send a discovery frame for InternetGatewayDevice, since some devices respond
// to ssdp:all with only their first descriptor (which is often not IGD).
// https://github.com/tailscale/tailscale/issues/3557
var uPnPIGDPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

type discoResponse struct {
	Location string

	// Server describes what version the UPnP is, such as MiniUPnPd/2.x.x
	Server string

	// USN is the serial number of the device, which also contains
	// what kind of UPnP service is being offered, i.e. InternetGatewayDevice:2
	USN string
}
