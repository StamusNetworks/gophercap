/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

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
package fs

import (
	"context"
	"gopherCap/pkg/models"
	"io"
	"os"
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
		p.Counters.Size = len(data)

		var last time.Time

		// No scan, need to iterate over entire file
		for {
			data, ci, err = h.ReadPacketData()

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

	return p.Do(fn)
}

func (p Pcap) open() (io.ReadCloser, error) { return Open(p.Path) }
