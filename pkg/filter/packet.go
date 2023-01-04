/*
Copyright © 2022 Stamus Networks oss@stamus-networks.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package filter

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DecapGREandERSPAN(pkt gopacket.Packet, maxdepth int) (gopacket.Packet, error) {
	var startLayer int
loop:
	for i, layer := range pkt.Layers() {
		if maxdepth > 0 && i+1 == maxdepth {
			// this can be a good performance optimization to only loop over N posterior layers
			break loop
		}
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
	return inner, nil
}
