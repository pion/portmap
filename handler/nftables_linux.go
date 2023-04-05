package handler

import "net"

type NFTablesMapping struct{}

func (m *NFTablesMapping) Close() error {
	// TODO
	return nil
}

type NFTablesMappingHandler struct{}

func NewNFTablesMappingHandler(table string) (*NFTablesMappingHandler, error) {
	// TODO
	return &NFTablesMappingHandler{}, nil
}

func (h *NFTablesMappingHandler) SetupMapping(proto string, extPort, intPort uint16, dst net.IP) (*NFTablesMapping, error) {
	// TODO
	return &NFTablesMapping{}, nil
}
