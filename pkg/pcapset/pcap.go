/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

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
