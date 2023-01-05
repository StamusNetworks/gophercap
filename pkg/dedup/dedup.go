package dedup

import (
	"crypto/md5"
	"encoding/hex"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HashMD5 is inspired by packet deduplication in Arkime
// https://github.com/arkime/arkime/blob/main/capture/dedup.c#L57
func HashMD5(pkt gopacket.Packet) []byte {
	h := md5.New()
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
			// we only want TCP or UDP packets to be deduplicated
			// hashing every packet could cause problems with ICMP or more obscure protocols
			return h.Sum(nil)
		}
	}
	return nil
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
	if h == nil {
		return false
	}
	key := hex.EncodeToString(h)
	if d.Set[key] {
		found = true
		d.Hits++
	}
	d.Set[key] = true
	return found
}

// CircularDedup maintains N buckets of hash sets
// hash lookup is done from all
// if hash is not found, add to latest
// rotate buckets if bucket duration has passed
type CircularDedup struct {
	// circular array of hash sets
	Buckets []map[string]bool
	// max number of buckets to be kept
	MaxBuckets int
	// max duration of each bucket
	Duration time.Duration
	// timestamp of latest bucket
	Bucket time.Time
}

func (cd *CircularDedup) Drop(pkt gopacket.Packet) (found bool) {
	count := len(cd.Buckets)
	if count == 0 {
		cd.Buckets = make([]map[string]bool, 0, cd.MaxBuckets)
		cd.Buckets[0] = make(map[string]bool)
	}
	h := HashMD5(pkt)
	if h == nil {
		return false
	}
	key := hex.EncodeToString(h)
	for _, bucket := range cd.Buckets {
		if bucket[key] {
			found = true
		}
	}
	if !found {
		cd.Buckets[len(cd.Buckets)-1][key] = true
	}
	// check if new bucket needs to be added
	if time.Since(cd.Bucket) > cd.Duration {
		cd.Buckets = append(cd.Buckets, map[string]bool{})
		cd.Bucket = time.Now().Truncate(cd.Duration)
		// drop last bucket if oversized
		if count+1 > cd.MaxBuckets {
			cd.Buckets = cd.Buckets[1:]
		}
	}
	return found
}

func NewCircularDedup(max int, duration time.Duration) *CircularDedup {
	cd := &CircularDedup{}
	if max < 2 {
		cd.MaxBuckets = 2
	} else {
		cd.MaxBuckets = max
	}
	if duration == 0 {
		cd.Duration = 2 * time.Second
	} else {
		cd.Duration = duration
	}
	cd.Buckets = make([]map[string]bool, 1, max)
	cd.Buckets[0] = make(map[string]bool)
	cd.Bucket = time.Now().Truncate(cd.Duration)
	return cd
}
