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
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

func buildBPF(event Event) (string, error) {
	proto := event.Proto
	srcIp := event.SrcIP
	destIp := event.DestIP
	srcPort := event.SrcPort
	destPort := event.DestPort
	if event.Tunnel.Depth != 0 {
		proto = event.Tunnel.Proto
		srcIp = event.Tunnel.SrcIP
		destIp = event.Tunnel.DestIP
		srcPort = event.Tunnel.SrcPort
		destPort = event.Tunnel.DestPort
	}
	bpfFilter := "proto " + proto + " and "
	switch proto {
	case "TCP", "UDP":
		bpfFilter += "("
		bpfFilter += fmt.Sprintf("(src host %s and src port %d and dst host %s and dst port %d)", srcIp, srcPort, destIp, destPort)
		bpfFilter += " or "
		bpfFilter += fmt.Sprintf("(src host %s and src port %d and dst host %s and dst port %d)", destIp, destPort, srcIp, srcPort)
		bpfFilter += ")"
	case "GRE":
		bpfFilter += "("
		if event.Tunnel.Depth != 0 {
			bpfFilter += fmt.Sprintf("host %v and host %v", event.Tunnel.SrcIP, event.Tunnel.DestIP)
		} else {
			bpfFilter += fmt.Sprintf("host %v and host %v", event.SrcIP, event.DestIP)
		}
		bpfFilter += ")"
	default:
		return "", errors.New("Protocol not supported")
	}
	logrus.Debugln(bpfFilter)
	return bpfFilter, nil
}

func buildEndpoints(event Event) (gopacket.Flow, gopacket.Flow, error) {
	srcIPEndpoint := layers.NewIPEndpoint(net.ParseIP(event.SrcIP))
	destIPEndpoint := layers.NewIPEndpoint(net.ParseIP(event.DestIP))
	IPFlow, err := gopacket.FlowFromEndpoints(srcIPEndpoint, destIPEndpoint)
	if err != nil {
		logrus.Error("Can not create IP Flow: ", err)
	}

	var srcEndpoint gopacket.Endpoint
	var destEndpoint gopacket.Endpoint
	switch event.Proto {
	case "TCP":
		srcEndpoint = layers.NewTCPPortEndpoint(layers.TCPPort(event.SrcPort))
		destEndpoint = layers.NewTCPPortEndpoint(layers.TCPPort(event.DestPort))
	case "UDP":
		srcEndpoint = layers.NewUDPPortEndpoint(layers.UDPPort(event.SrcPort))
		destEndpoint = layers.NewUDPPortEndpoint(layers.UDPPort(event.DestPort))
	case "SCTP":
		srcEndpoint = layers.NewSCTPPortEndpoint(layers.SCTPPort(event.SrcPort))
		destEndpoint = layers.NewSCTPPortEndpoint(layers.SCTPPort(event.DestPort))
	default:
		return IPFlow, gopacket.InvalidFlow, errors.New("Unsupported protocol " + event.Proto)
	}

	transportFlow, err := gopacket.FlowFromEndpoints(srcEndpoint, destEndpoint)
	if err != nil {
		logrus.Error("Can not create transport Flow", err)
	}
	return IPFlow, transportFlow, err
}

func filterTunnel(data []byte, IPFlow gopacket.Flow, transportFlow gopacket.Flow, event Event) bool {
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
						logrus.Error("Unsupported tunnel type: " + event.Tunnel.Proto)
					}
					actualPacket := gopacket.NewPacket(tLayer.LayerPayload(), layers.LayerTypeIPv4, gopacket.Lazy)
					networkLayer = actualPacket.NetworkLayer()
				}
				nFlow := networkLayer.NetworkFlow()
				if nFlow == IPFlow || nFlow == IPFlow.Reverse() {
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
