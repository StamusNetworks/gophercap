package dedup

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type pktParams struct {
	srcIP    net.IP
	destIP   net.IP
	srcMAC   net.HardwareAddr
	destMac  net.HardwareAddr
	srcPort  uint16
	destPort uint16
	ttl      uint8
	csum     uint16
}

type v4params struct {
	pktParams
}

func buildPacketIPv4(p v4params) []byte {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       p.srcMAC,
		DstMAC:       p.destMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      p.ttl,
		SrcIP:    p.srcIP,
		DstIP:    p.destIP,
		Checksum: p.csum,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(p.srcPort),
		DstPort: layers.TCPPort(p.destPort),
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	rawBytes := []byte{10, 20, 30}

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	// And create the packet with the layers
	if err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	); err != nil {
		// FIXME
	}
	return buffer.Bytes()
}

func TestHashV4(t *testing.T) {
	opts := gopacket.DecodeOptions{
		Lazy:   false,
		NoCopy: false,
	}
	firstLayer := layers.LayerTypeEthernet
	hashOrig := HashMD5(gopacket.NewPacket(
		buildPacketIPv4(v4params{
			pktParams: pktParams{
				srcIP:    net.IP{127, 0, 0, 1},
				destIP:   net.IP{8, 8, 8, 8},
				srcMAC:   net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
				destMac:  net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
				srcPort:  29999,
				destPort: 80,
				ttl:      13,
				csum:     uint16(12379),
			},
		}),
		firstLayer,
		opts))
	// TTL and checksum should not affect hash result
	hashIdentical := HashMD5(gopacket.NewPacket(
		buildPacketIPv4(v4params{
			pktParams: pktParams{
				srcIP:    net.IP{127, 0, 0, 1},
				destIP:   net.IP{8, 8, 8, 8},
				srcMAC:   net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
				destMac:  net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
				srcPort:  29999,
				destPort: 80,
				ttl:      99,
				csum:     uint16(7893),
			},
		}),
		firstLayer,
		opts))
	if hashOrig != hashIdentical {
		t.Fatal("TTL and checksum should not affect IPv4 packet results")
	}
	hashDiffIP := HashMD5(gopacket.NewPacket(
		buildPacketIPv4(v4params{
			pktParams: pktParams{
				srcIP:    net.IP{127, 0, 0, 1},
				destIP:   net.IP{8, 8, 4, 4},
				srcMAC:   net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
				destMac:  net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
				srcPort:  30000,
				destPort: 80,
				ttl:      99,
				csum:     uint16(7893),
			},
		}),
		firstLayer,
		opts))
	if hashOrig == hashDiffIP {
		fmt.Println(hashOrig)
		fmt.Println(hashDiffIP)
		t.Fatal("dest IP change should change hash result")
	}
}
