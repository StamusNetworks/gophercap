/*
Copyright © 2021 Stamus Networks oss@stamus-networks.com

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
package extract

import (
	"errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"
	"fmt"

	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)


func writePacket(handle *pcap.Handle, buf []byte) error {
	if err := handle.WritePacketData(buf); err != nil {
		logrus.Warning("Failed to write packet: %s\n", err)
		return err
	}
	return nil
}

type Tunnel struct {
	Src_ip string
	Dest_ip string
	Src_port uint16
	Dest_port uint16
	Proto string
	Depth uint8
}

type Alert struct {
	Timestamp string
	Src_ip string
	Dest_ip string
	Src_port uint16
	Dest_port uint16
	App_proto string
	Proto string
	Tunnel Tunnel
}

func buildBPF(event Alert) string {
	proto := event.Proto
	src_ip := event.Src_ip
	dest_ip := event.Dest_ip
	src_port := event.Src_port
	dest_port := event.Dest_port
	if event.Tunnel.Depth != 0 {
		proto = event.Tunnel.Proto
		src_ip = event.Tunnel.Src_ip
		dest_ip = event.Tunnel.Dest_ip
	}
	bpfFilter := "proto " + proto + " and "
	switch proto {
	case "TCP", "UDP":
		bpfFilter += "("
		bpfFilter += fmt.Sprintf("(src host %v and src port %v and dst host %v and dst port %v)", src_ip, src_port, dest_ip, dest_port)
		bpfFilter += " or "
		bpfFilter += fmt.Sprintf("(src host %v and src port %v and dst host %v and dst port %v)", dest_ip, dest_port, src_ip, src_port)
		bpfFilter += ")"
	case "GRE":
		bpfFilter += "("
		if event.Tunnel.Depth != 0 {
			bpfFilter += fmt.Sprintf("host %v and host %v", event.Tunnel.Src_ip, event.Tunnel.Dest_ip)
		} else {
			bpfFilter += fmt.Sprintf("host %v and host %v", event.Src_ip, event.Dest_ip)
		}
		bpfFilter += ")"
	default:
		logrus.Fatal("Protocol unsupported")
	}
	return bpfFilter
}

func builEndpoints(event Alert) (gopacket.Flow, gopacket.Flow) {
	srcIPEndpoint := layers.NewIPEndpoint(net.ParseIP(event.Src_ip))
	destIPEndpoint := layers.NewIPEndpoint(net.ParseIP(event.Dest_ip))
	IPFlow, err := gopacket.FlowFromEndpoints(srcIPEndpoint, destIPEndpoint)
	if err != nil {
		logrus.Fatal("Can not create IP Flow", err)
	}

	var srcEndpoint gopacket.Endpoint
	var destEndpoint gopacket.Endpoint
	switch event.Proto {
	case "TCP":
		srcEndpoint = layers.NewTCPPortEndpoint(layers.TCPPort(event.Src_port))
		destEndpoint = layers.NewTCPPortEndpoint(layers.TCPPort(event.Dest_port))
	case "UDP":
		srcEndpoint = layers.NewUDPPortEndpoint(layers.UDPPort(event.Src_port))
		destEndpoint = layers.NewUDPPortEndpoint(layers.UDPPort(event.Dest_port))
	case "SCTP":
		srcEndpoint = layers.NewSCTPPortEndpoint(layers.SCTPPort(event.Src_port))
		destEndpoint = layers.NewSCTPPortEndpoint(layers.SCTPPort(event.Dest_port))
	default:
		logrus.Fatal("Protocol unsupported " + event.Proto)
		return IPFlow, gopacket.InvalidFlow
	}

	transportFlow, err := gopacket.FlowFromEndpoints(srcEndpoint, destEndpoint)
	if err != nil {
		logrus.Fatal("Can not create transport Flow", err)
	}
	return IPFlow, transportFlow
}

func filterTunnel(data []byte, IPFlow gopacket.Flow, transportFlow gopacket.Flow, event Alert) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
	switch event.Proto {
	case "TCP":
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.TransportFlow() == transportFlow || tcp.TransportFlow() == transportFlow.Reverse() {
				/* TODO handle depth > 1 */
				networkLayer := packet.NetworkLayer()
				if event.Tunnel.Depth > 0 {
					var tLayer gopacket.Layer
					switch event.Tunnel.Proto {
					case "GRE":
						tLayer = packet.Layer(layers.LayerTypeGRE)
					case "VXLAN":
						tLayer = packet.Layer(layers.LayerTypeVXLAN)
					default:
						logrus.Fatal("Unsupported tunnel type: " + event.Tunnel.Proto)
					}
					actualPacket := gopacket.NewPacket(tLayer.LayerPayload(), layers.LayerTypeIPv4, gopacket.Lazy)
					networkLayer = actualPacket.NetworkLayer()
				}
				nFlow := networkLayer.NetworkFlow()
				if nFlow == IPFlow  ||  nFlow == IPFlow.Reverse()  {
					return true
				}
			}
		}
	case "UDP":
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		/* TODO handle tunnel in UDP */
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if udp.TransportFlow() == transportFlow || udp.TransportFlow() == transportFlow.Reverse() {
				return true
			}
		}
	case "SCTP":
		sctpLayer := packet.Layer(layers.LayerTypeSCTP)
		/* TODO handle tunnel in SCTP */
		if sctpLayer != nil {
			sctp, _ := sctpLayer.(*layers.SCTP)
			if sctp.TransportFlow() == transportFlow || sctp.TransportFlow() == transportFlow.Reverse() {
				return true
			}
		}
	}
	return false
}


/*
Extract a pcap file for a given flow
*/
func ExtractPcapFile(fname string, oname string, eventdata string) error {
	/* open event file */
	eventfile, err := os.Open(eventdata)
	if err != nil {
		return err
	}
	defer eventfile.Close()

	eventdatastring, err := ioutil.ReadAll(eventfile)
	if err != nil {
		return err
	}

	var event Alert
	err = json.Unmarshal(eventdatastring, &event)
	if err != nil {
		return errors.New("Can't parse JSON in " + eventdata)
	}
	if event.Tunnel.Depth != 0 {
		logrus.Debugf("Tunnel: %v <-%v-> %v\n", event.Tunnel.Src_ip, event.Tunnel.Proto, event.Tunnel.Dest_ip)
	}
	logrus.Debugf("Flow: %v <-%v:%v-> %v\n", event.Src_ip, event.Proto, event.App_proto, event.Dest_ip)
	IPFlow, transportFlow := builEndpoints(event)
	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(fname)
	if err != nil {
		return err
	}
	defer handleRead.Close()

	err = handleRead.SetBPFFilter(buildBPF(event))
	if err != nil {
		logrus.Fatal("Invalid BPF Filter: %v", err)
		return err
	}
	// Open up a second pcap handle for packet writes.
	outfile, err := os.Create(oname);
	if err != nil {
		logrus.Fatal("Can't open pcap output file:", err)
		return err
	}
	defer outfile.Close()

	handleWrite := pcapgo.NewWriter(outfile)
	handleWrite.WriteFileHeader(65536, layers.LinkTypeEthernet)  // new file, must do this.
	if err != nil {
		logrus.Fatal("Can't write to output file:", err)
		return err
	}

	start := time.Now()
	pkt := 0

	// Loop over packets and write them
	for {
		data, ci, err := handleRead.ReadPacketData()

		switch {
		case err == io.EOF:
			logrus.Infof("Finished in %s\n", time.Since(start))
			logrus.Infof("Written %v packet(s)\n", pkt)
			return nil
		case err != nil:
			logrus.Warningf("Failed to read packet %d: %s\n", pkt, err)
		default:
			if event.Tunnel.Depth > 0 {
				if filterTunnel(data, IPFlow, transportFlow, event) {
					handleWrite.WritePacket(ci, data)
					pkt++
				}
			} else {
				handleWrite.WritePacket(ci, data)
				pkt++
			}
		}
	}

	return nil
}
