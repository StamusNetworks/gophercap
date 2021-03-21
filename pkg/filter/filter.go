package filter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

// BPFLogicGate is a logical joiner for BPF data
type BPFLogicGate int

const (
	// BPFOr is a logical OR gate
	BPFOr BPFLogicGate = iota
	// BPFAnd is a logical AND gate
	BPFAnd
)

func (b BPFLogicGate) String() string {
	switch b {
	case BPFAnd:
		return " and "
	default:
		return " or "
	}
}

// BPFNet is a handler for generating valid BPF filters from structured type-safe data
// this one generates network filter
// TODO - implement a interface to combine any number of BPF generators
type BPFNet struct {
	Networks []net.IPNet
	Gate     BPFLogicGate
}

func (b BPFNet) Contains(ip net.IP) bool {
	for _, net := range b.Networks {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// NewBPFNet initializes a new BPFNet object from a list of networks and a logic joiner requirement
func NewBPFNet(nets []string, join BPFLogicGate) (*BPFNet, error) {
	if nets == nil || len(nets) == 0 {
		return nil, errors.New("Missing network list")
	}
	parsedNets := make([]net.IPNet, len(nets))
	for i, network := range nets {
		_, parsed, err := net.ParseCIDR(network)
		if err != nil || parsed == nil {
			return nil, fmt.Errorf("Invalid network %s", network)
		}
		parsedNets[i] = *parsed
	}
	return &BPFNet{Networks: parsedNets, Gate: join}, nil
}

func (b BPFNet) String() string {
	nets := make([]string, len(b.Networks))
	for i, network := range b.Networks {
		nets[i] = "net " + network.String()
	}
	return strings.Join(nets, b.Gate.String())
}

// BPFNetMap is a container to hold BPF network maps
type BPFNetMap map[string]BPFNet

// PktFunc is called per packet. User can implement custom code to handle or filter packets
type PktFunc func(gopacket.Packet, *pcapgo.Writer, BPFNet) bool

// DefaultPktFunc - just write the packet as-is and assume that filtering is already
// done by BPF filter on reader side
func DefaultPktFunc(pkt gopacket.Packet, w *pcapgo.Writer, bpfNet BPFNet) bool {
	w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
	return true
}

func FilteredPktFunc(pkt gopacket.Packet, w *pcapgo.Writer, bpfNet BPFNet) bool {
	src, dest := pkt.NetworkLayer().NetworkFlow().Endpoints()
	srcIP := net.ParseIP(src.String())
	destIP := net.ParseIP(dest.String())
	if srcIP == nil || destIP == nil {
		return false
	}
	if bpfNet.Contains(srcIP) || bpfNet.Contains(destIP) {
		w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     pkt.Metadata().Timestamp,
			CaptureLength: len(pkt.Data()),
			Length:        len(pkt.Data()),
		}, pkt.Data())
		return true
	}
	return false
}

func DecapPktFunc(pkt gopacket.Packet, w *pcapgo.Writer, bpfNet BPFNet) bool {
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
		return DefaultPktFunc(pkt, w, bpfNet)
	}
	// paranoia check
	if startLayer == len(pkt.Layers())-1 {
		return false
	}
	inner := gopacket.NewPacket(
		pkt.Layers()[startLayer].LayerPayload(),
		pkt.Layers()[startLayer+1].LayerType(),
		gopacket.Lazy,
	)

	if inner == nil || inner.NetworkLayer() == nil {
		return false
	}
	return FilteredPktFunc(inner, w, bpfNet)
}

// Config holds params needed by ReadAndFilterNetworks
type Config struct {
	// Full path for input and otput PCAP files
	InFile, OutFile string
	// BPF filter object, only packets matching network list will be written to OutFile
	Filter BPFNet
	// function to be called per packet
	PktFunc PktFunc
	// Optionally disable native libpcap BPF call
	// Use this when callaing DecapPktFunc
	// BPF would otherwise filter all transport packets that have wrong IP
	DisableNativeBPF bool
}

/*
ReadAndFilterNetworks is a simple function that takes filter packets matching BPF filter from input file
to output file.
*/
func ReadAndFilterNetworks(c *Config) error {
	if c.PktFunc == nil {
		logrus.Warn("Packet handling function undefined, using default")
		c.PktFunc = DefaultPktFunc
	}
	var count int64
	input, err := pcap.OpenOffline(c.InFile)
	if err != nil {
		return err
	}
	defer input.Close()

	if !c.DisableNativeBPF {
		if err := input.SetBPFFilter(c.Filter.String()); err != nil {
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(input, input.LinkType())

	output, err := os.Create(c.OutFile)
	if err != nil {
		return err
	}
	defer output.Close()

	logrus.Infof("writing %s snaplen %d\n", c.OutFile, input.SnapLen())
	w := pcapgo.NewWriter(output)
	w.WriteFileHeader(uint32(input.SnapLen()), input.LinkType())

	for packet := range packetSource.Packets() {
		if c.PktFunc(packet, w, c.Filter) {
			count++
		}
	}
	logrus.Infof("%s wrote %d packets", c.OutFile, count)
	return nil
}

// Task is input file to be fed to filter reader, along with BPF filter used to extract packets
type Task struct {
	Input, Output string

	Filter BPFNet
}