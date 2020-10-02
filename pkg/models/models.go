package models

import "time"

type Period struct {
	Beginning time.Time `json:"beginning"`
	End       time.Time `json:"end"`
}

func (p Period) Duration() time.Duration {
	return p.End.Sub(p.Beginning)
}

func (p Period) Delay(target time.Time) time.Duration {
	return p.Beginning.Sub(target)
}

type Counters struct {
	Packets       int `json:"packets"`
	Size          int `json:"size"`
	MaxPacketSize int `json:"max_packet_size"`
}

func (c Counters) PPS(interval time.Duration) float64 {
	return float64(c.Packets) / interval.Seconds()
}

type Rates struct {
	PPS           float64       `json:"pps"`
	Duration      time.Duration `json:"duration"`
	DurationHuman string        `json:"duration_human"`
}
