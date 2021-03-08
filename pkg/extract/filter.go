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


func buildBPF(event Alert) (string, error) {
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
		return "", errors.New("Protocol not supported")
	}
	logrus.Debugln(bpfFilter)
	return bpfFilter, nil
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


