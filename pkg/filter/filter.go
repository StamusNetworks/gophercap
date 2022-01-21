package filter

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type ConfigFileInput map[string][]string

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
	// Optionally disable native libpcap BPF call
	// Use this when callaing DecapPktFunc
	// BPF would otherwise filter all transport packets that have wrong IP
	DisableNativeBPF bool

	Compress struct {
		Input  bool
		Output bool
	}

	StatFunc func(FilterResult)
}

type FilterResult struct {
	Count       int
	Matched     int
	Errors      int
	DecapErrors int
	Skipped     int
	Start       time.Time
	Took        time.Duration
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
	if c.Compress.Output {
		fp += ".gz"
	}
	output, err := os.Create(fp)
	if err != nil {
		return nil, fmt.Errorf("outfile create: %s", err)
	}
	defer output.Close()

	if c.Compress.Output {
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

loop:
	for {
		select {
		case <-report.C:
			if c.StatFunc != nil {
				c.StatFunc(*res)
			}
		default:
		}
		res.Count++

		raw, _, err := input.ReadPacketData()
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
		if c.Filter.Match(pkt) {
			if err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
				res.Errors++
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

	Filter Matcher
}
