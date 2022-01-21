package filter

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConditionKind int

const (
	ConditionKindTCP ConditionKind = iota
	ConditionKindUDP
)

// Matcher is for filtering packets
type Matcher interface {
	// Match should indicate if packet matches criteria
	Match(gopacket.Packet) bool
}

// NewConditionalSubnet parses a list of textual network addrs into a Matcher
func NewConditionalSubnet(nets []string) (ConditionSubnet, error) {
	if len(nets) == 0 {
		return nil, errors.New("no networks to parse into contition")
	}
	tx := make([]net.IPNet, 0, len(nets))
	for _, n := range nets {
		_, parsed, err := net.ParseCIDR(n)
		if err != nil {
			return tx, err
		}
		tx = append(tx, *parsed)
	}
	return tx, nil
}

type ConditionSubnet []net.IPNet

func (cs ConditionSubnet) Match(pkt gopacket.Packet) bool {
	if n := pkt.NetworkLayer(); n != nil {
		return cs.match(net.ParseIP(n.NetworkFlow().Src().String())) ||
			cs.match(net.ParseIP(n.NetworkFlow().Dst().String()))
	}
	return false
}

func (cs ConditionSubnet) match(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, net := range cs {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func NewPortMatcher(k ConditionKind, p ...uint16) *ConditionEndpoint {
	vals := make(map[gopacket.Endpoint]bool)
	for _, port := range p {
		switch k {
		case ConditionKindTCP:
			vals[layers.NewTCPPortEndpoint(layers.TCPPort(port))] = true
		case ConditionKindUDP:
			vals[layers.NewUDPPortEndpoint(layers.UDPPort(port))] = true
		}
	}
	return &ConditionEndpoint{Values: vals}
}

type ConditionEndpoint struct {
	Values map[gopacket.Endpoint]bool
}

func (cs ConditionEndpoint) Match(pkt gopacket.Packet) bool {
	if t := pkt.TransportLayer(); t != nil {
		tf := t.TransportFlow()
		return cs.match(tf.Src()) || cs.match(tf.Dst())
	}
	return false
}

func (cs ConditionEndpoint) match(v gopacket.Endpoint) bool {
	return cs.Values[v]
}
