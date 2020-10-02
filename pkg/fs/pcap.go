package fs

import (
	"context"
	"io"
	"os"
	"gopherCap/pkg/models"
	"time"

	"github.com/google/gopacket/pcapgo"
)

/*
Pcap is the main handler for PCAP files, holding filesystem and parsed PCAP metadata.
It can also hold error values when processing files concurrently.
*/
type Pcap struct {
	Path string `json:"path"`
	Root string `json:"root"`

	Err error `json:"err"`

	Snaplen uint32 `json:"snaplen"`

	models.Counters
	models.Period
	models.Rates

	fi os.FileInfo
}

// Duration wraps around models.Period Duration method
func (p Pcap) Duration() time.Duration {
	return p.Period.Duration()
}

// PPS wraps around models.Counters PPS method
func (p Pcap) PPS() float64 {
	return p.Counters.PPS(p.Duration())
}

// Calculate is a setter for updating pcap metadata
func (p *Pcap) Calculate() *Pcap {
	p.Rates = models.Rates{
		Duration:      p.Duration(),
		DurationHuman: p.Duration().String(),
		PPS:           p.PPS(),
	}
	return p
}

/*
Do manages opening and closing a user-defined pcap file handle, and executes concurrent
user-defined WorkerFunc
*/
func (p Pcap) Do(w WorkerFunc) error {
	h, err := p.open()
	if err != nil {
		return err
	}
	defer h.Close()
	if err := w(h); err != nil {
		return err
	}
	return nil
}

/*
ScanPeriod is a wrapper around WorkerFunc that extracts first and last timestamp from
pcap file, while also calculating sumber of pacets and file size
*/
func (p *Pcap) ScanPeriod(ctx context.Context) error {
	fn := func(r io.Reader) error {
		h, err := pcapgo.NewReader(r)
		if err != nil {
			return err
		}
		// Get first packet
		data, ci, err := h.ReadPacketData()
		if err != nil {
			return err
		}
		p.Period.Beginning = ci.Timestamp

		var last time.Time

		// No scan, need to iterate over entire file
		for {
			_, ci, err := h.ReadPacketData()

			if err != nil && err == io.EOF {
				break
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

		return nil

	}

	if err := p.Do(fn); err != nil {
		return err
	}

	return nil
}

func (p Pcap) open() (io.ReadCloser, error) { return Open(p.Path) }
