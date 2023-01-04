package dedup

import (
	"crypto/md5"
	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HashMD5 is inspired by packet deduplication in Arkime
// https://github.com/arkime/arkime/blob/main/capture/dedup.c#L57
func HashMD5(pkt gopacket.Packet) string {
	h := md5.New()
loop:
	for _, layer := range pkt.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			data := layer.LayerContents()
			h.Write(data[0:7])
			// skip TTL
			h.Write(data[9:9])
			// skip checksum
			h.Write(data[13:])
		case layers.LayerTypeIPv6:
			data := layer.LayerContents()
			h.Write(data[0:6])
			// skip hop limit
			h.Write(data[8:])
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			h.Write(layer.LayerContents())
			// TCP / UDP layer is the innermost we want to hash
			break loop
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
