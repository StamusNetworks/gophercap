package filter

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type ErrEarlyExit struct{}

func (e ErrEarlyExit) Error() string { return "early exit" }

// Config holds params needed by ReadAndFilterNetworks
type Config struct {
	ID int
	// Full path for input and otput PCAP files
	File struct {
		Input  string
		Output string
	}
	// BPF filter object, only packets matching network list will be written to OutFile
	Filter Matcher
	// Enable GRE and ERSPAN packet decapsulation
	Decapsulate bool

	Compress bool

	StatFunc func(FilterResult)

	Ctx context.Context
}

type FilterResult struct {
	Count       int
	Matched     int
	Errors      int
	DecapErrors int
	Skipped     int
	Start       time.Time
	Took        time.Duration
	Rate        string
}

/*
ReadAndFilter processes a PCAP file, storing packets that match filtering
criteria in output file
*/
func ReadAndFilter(c *Config) (*FilterResult, error) {
	f, err := os.Open(c.File.Input)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	input, err := pcapgo.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("infile open: %s", err)
	}
	input.SetSnaplen(1024 * 64)

	var writer io.Writer
	fp := c.File.Output
	if c.Compress {
		fp += ".gz"
	}
	output, err := os.Create(fp)
	if err != nil {
		return nil, fmt.Errorf("outfile create: %s", err)
	}
	defer output.Close()

	if c.Compress {
		gw := gzip.NewWriter(output)
		defer gw.Close()
		writer = gw
	} else {
		writer = output
	}

	w := pcapgo.NewWriter(writer)
	w.WriteFileHeader(uint32(input.Snaplen()), input.LinkType())

	report := time.NewTicker(5 * time.Second)

	res := &FilterResult{Start: time.Now()}

	var ctx context.Context
	if c.Ctx == nil {
		ctx = context.Background()
	} else {
		ctx = c.Ctx
	}

loop:
	for {
		select {
		case <-ctx.Done():
			return res, ErrEarlyExit{}
		case <-report.C:
			res.Took = time.Since(res.Start)
			res.Rate = fmt.Sprintf("%.2f pps", float64(res.Count)/res.Took.Seconds())
			if c.StatFunc != nil {
				c.StatFunc(*res)
			}
		default:
		}
		res.Count++

		raw, ci, err := input.ReadPacketData()
		if err != nil && err == io.EOF {
			break loop
		} else if err != nil {
			res.Errors++
			continue loop
		}
		pkt := gopacket.NewPacket(raw, input.LinkType(), gopacket.Default)
		if c.Decapsulate {
			pkt, err = DecapGREandERSPAN(pkt)
			if err != nil {
				res.DecapErrors++
				continue loop
			}
		}
		ci.CaptureLength = len(pkt.Data())
		pkt.Metadata().CaptureInfo = ci
		if c.Filter.Match(pkt) {
			if err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
				return res, err
			}
			res.Matched++
		} else {
			res.Skipped++
		}
	}
	return res, nil
}

// Task is input file to be fed to filter reader, along with BPF filter used to extract packets
type Task struct {
	Input, Output string

	Filter      Matcher
	Description string
}
