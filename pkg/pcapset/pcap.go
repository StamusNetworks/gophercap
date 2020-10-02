package pcapset

import (
	"gopherCap/pkg/fs"
	"time"
)

/*
Pcap is a wrapper around fs.Pcap with additional delay tracking
*/
type Pcap struct {
	fs.Pcap
	Delay      time.Duration `json:"delay"`
	DelayHuman string        `json:"delay_human"`
}

func (p Pcap) setDelay(delay time.Duration) Pcap {
	p.Delay = delay
	p.DelayHuman = p.Delay.String()
	return p
}
