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

// Dedupper is a subsystem that accepts a gopacket type and reports if it has been already seen
type Dedupper interface {
	// Drop implements Dedupper
	Drop(gopacket.Packet) bool
}

// TrivialDedup is only a minimal prototype for simple testing and SHOULD NOT BE USED
// It will leak memory and will likely see a high hash collision rate
type TrivialDedup struct {
	Set  map[string]bool
	Hits uint64
}

// Drop implements Dedupper
func (d *TrivialDedup) Drop(pkt gopacket.Packet) (found bool) {
	if d.Set == nil {
		// this object should not have a constructor
		d.Set = make(map[string]bool)
	}
	h := HashMD5(pkt)
	if d.Set[h] {
		found = true
		d.Hits++
	}
	d.Set[h] = true
	return found
}
