package replay

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/StamusNetworks/gophercap/pkg/models"

	"github.com/google/gopacket/pcapgo"
)

type Pcap struct {
	Path string `json:"path"`

	Snaplen uint32 `json:"snaplen"`

	models.Counters
	models.Period
	models.Rates

	Delay      time.Duration `json:"delay"`
	DelayHuman string        `json:"delay_human"`
}

func scan(path string, ctx context.Context) (*Pcap, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	p := &Pcap{
		Path: path,
	}
	h, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, err
	}
	// Get first packet
	data, ci, err := h.ReadPacketData()
	if err != nil {
		return nil, err
	}
	p.Period.Beginning = ci.Timestamp
	p.Counters.Size = len(data)

	var last time.Time

loop:
	for {
		data, ci, err = h.ReadPacketData()

		if err != nil {
			if err == io.EOF {
				break loop
			} else {
				return nil, err
			}
		}
		if !ci.Timestamp.After(last) {
			p.Counters.OutOfOrder++
		}
		last = ci.Timestamp
		size := len(data)
		p.Counters.Packets++
		p.Counters.Size += size
		if size > p.MaxPacketSize {
			p.MaxPacketSize = size
		}
	}
	p.Period.End = last
	p.Snaplen = h.Snaplen()
	p.Rates.Duration = p.Period.Duration()
	p.Rates.DurationHuman = p.Rates.Duration.String()
	p.Rates.PPS = p.Counters.PPS(p.Rates.Duration)
	return p, nil
}

/*
open opens a file handle while accounting for compression extracted from file magic
*/
func Open(path string) (io.ReadCloser, error) {
	if path == "" {
		return nil, errors.New("Missing file path")
	}
	m, err := magic(path)
	if err != nil {
		return nil, err
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if m == Gzip {
		gzipHandle, err := gzip.NewReader(handle)
		if err != nil {
			return nil, err
		}
		return gzipHandle, nil
	}
	return handle, nil
}
