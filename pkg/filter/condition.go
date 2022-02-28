/*
Copyright © 2022 Stamus Networks oss@stamus-networks.com

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
package filter

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/oschwald/geoip2-golang"
)

type FilterKind int

const (
	FilterKindUndefined FilterKind = iota
	FilterKindSubnet
	FilterKindPort
	FilterKindASN
)

func (k FilterKind) String() string {
	switch k {
	case FilterKindSubnet:
		return "subnet"
	case FilterKindPort:
		return "port"
	case FilterKindASN:
		return "asn"
	default:
		return "undefined"
	}
}

var FilterKinds = []string{
	FilterKindSubnet.String(),
	FilterKindPort.String(),
	FilterKindASN.String(),
}

func NewFilterKind(raw string) FilterKind {
	switch raw {
	case FilterKinds[0]:
		return FilterKindSubnet
	case FilterKinds[1]:
		return FilterKindPort
	case FilterKinds[2]:
		return FilterKindASN
	default:
		return FilterKindUndefined
	}
}

// Matcher is for filtering packets
type Matcher interface {
	// Match should indicate if packet matches criteria
	Match(gopacket.Packet) bool
}

// CombinedMatcher allows us to use multiple match criteria
type CombinedMatcher struct {
	Conditions []Matcher
}

func (cm CombinedMatcher) Match(pkt gopacket.Packet) bool {
	for _, matcher := range cm.Conditions {
		if !matcher.Match(pkt) {
			return false
		}
	}
	return true
}

func NewCombinedMatcher(c MatcherConfig) (*CombinedMatcher, error) {
	if len(c.Conditions) == 0 {
		return nil, errors.New("combined config condition missing")
	}
	conditions := make([]Matcher, 0, len(c.Conditions))
	for i, condition := range c.Conditions {
		var m Matcher
		switch NewFilterKind(condition.Kind) {
		case FilterKindSubnet:
			sm, err := NewConditionalSubnet(condition.Match)
			if err != nil {
				return nil, err
			}
			m = sm
		case FilterKindPort:
			pm, err := NewPortMatcher(condition.Match)
			if err != nil {
				return nil, err
			}
			m = pm
		case FilterKindASN:
			if c.MaxMindASN == "" {
				return nil, errors.New("asn matcher needs maxmind ASN database")
			}
			fa, err := NewConditionASN(c.MaxMindASN, condition.Match)
			if err != nil {
				return nil, err
			}
			m = fa
		default:
			return nil, fmt.Errorf(
				"filtering condition %s unsupported for condition %d, use one of %s",
				condition.Kind, i, strings.Join(FilterKinds, ", "),
			)
		}
		if m == nil {
			return nil, fmt.Errorf("unable to build matcher for item %d", i)
		}
		if condition.Negate {
			m = NegateMatcher{M: m}
		}
		conditions = append(conditions, m)
	}
	return &CombinedMatcher{
		Conditions: conditions,
	}, nil
}

// NegateMatcher implements logical NOT
type NegateMatcher struct {
	M Matcher
}

func (nm NegateMatcher) Match(pkt gopacket.Packet) bool { return !nm.M.Match(pkt) }

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

func NewPortMatcher(p []string) (ConditionEndpoint, error) {
	vals := make(map[gopacket.Endpoint]bool)
	for _, raw := range p {
		bits := strings.Split(raw, "/")
		if len(bits) != 2 {
			return nil, fmt.Errorf("%s not valid port format, should be <number>/<tcp/udp>", raw)
		}
		port, err := strconv.Atoi(bits[0])
		if err != nil {
			return nil, err
		}
		switch bits[1] {
		case "tcp":
			vals[layers.NewTCPPortEndpoint(layers.TCPPort(port))] = true
		case "udp":
			vals[layers.NewUDPPortEndpoint(layers.UDPPort(port))] = true
		default:
			return nil, fmt.Errorf(
				"protocol def invalid for %s, got %s, expected tcp or udp",
				raw,
				bits[1],
			)
		}
	}
	return vals, nil
}

type ConditionEndpoint map[gopacket.Endpoint]bool

func (cs ConditionEndpoint) Match(pkt gopacket.Packet) bool {
	if t := pkt.TransportLayer(); t != nil {
		tf := t.TransportFlow()
		return cs.match(tf.Src()) || cs.match(tf.Dst())
	}
	return false
}

func (cs ConditionEndpoint) match(v gopacket.Endpoint) bool {
	return cs[v]
}

type ConditionASN struct {
	Values      map[uint]bool
	DB          *geoip2.Reader
	LookupErrs  int
	IPParseErrs int
}

func (ca ConditionASN) Match(pkt gopacket.Packet) bool {
	if n := pkt.NetworkLayer(); n != nil {
		return ca.match(net.ParseIP(n.NetworkFlow().Src().String())) ||
			ca.match(net.ParseIP(n.NetworkFlow().Dst().String()))
	}
	return false
}

func (ca *ConditionASN) match(ip net.IP) bool {
	if ip == nil {
		ca.IPParseErrs++
		return false
	}
	resp, err := ca.DB.ASN(ip)
	if err != nil {
		ca.LookupErrs++
		return false
	}
	return ca.Values[resp.AutonomousSystemNumber]
}

func NewConditionASN(path string, asn []string) (*ConditionASN, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	conditions := make(map[uint]bool)
	for _, val := range asn {
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return nil, err
		}
		conditions[uint(parsed)] = true
	}
	return &ConditionASN{
		DB:     db,
		Values: conditions,
	}, nil
}
