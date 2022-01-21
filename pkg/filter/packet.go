package filter

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DecapGREandERSPAN(pkt gopacket.Packet) (gopacket.Packet, error) {
	var startLayer int
	for i, layer := range pkt.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeGRE:
			startLayer = i
		case layers.LayerTypeERSPANII:
			startLayer = i
		}
	}
	// Did not find any tunnel layers, assume no decap nor custom filtering is needed
	if startLayer == 0 {
		return pkt, nil
	}
	if len(pkt.Layers()) <= startLayer {
		return pkt, errors.New("layer len mismatch")
	}
	inner := gopacket.NewPacket(
		pkt.Layers()[startLayer].LayerPayload(),
		pkt.Layers()[startLayer+1].LayerType(),
		gopacket.Lazy,
	)

	if inner == nil || inner.NetworkLayer() == nil {
		return pkt, errors.New("unable to build inner packet")
	}
	return pkt, nil
}
