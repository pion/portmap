package handler

import "net"

type Mapping interface {
	Close() error
}

type MappingHandler interface {
	SetupMapping(proto string, extPort, intPort uint16, dst net.IP) (Mapping, error)
}
