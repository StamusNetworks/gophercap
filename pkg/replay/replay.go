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
package replay

import (
	"context"
	"errors"
	"gopherCap/pkg/models"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var DelayGrace = 100 * time.Microsecond

/*
Config is used for passing Handle configurations when creating a new replay object
*/
type Config struct {
	Set            PcapSet
	WriteInterface string
	FilterRegex    *regexp.Regexp
	OutBpf         string
	DisableWait    bool
	Reorder        bool

	ScaleDuration time.Duration
	ScaleEnabled  bool
	ScalePerFile  bool

	SkipOutOfOrder bool
	SkipMTU        int

	TimeFrom, TimeTo time.Time
	Ctx              context.Context
}

/*
Validate implements a standard interface for checking config struct validity and setting
sane default values.
*/
func (c Config) Validate() error {
	if c.Ctx == nil {
		return errors.New("missing replay stopper context")
	}
	if err := c.Set.Validate(); err != nil {
		return err
	}
	if c.ScaleEnabled && c.ScaleDuration == 0 {
		return errors.New("Time scaling enabled but duration not defined")
	}
	return nil
}

/*
Handle is the core object managing replay state
*/
type Handle struct {
	FileSet     PcapSet
	speedMod    float64
	scale       bool
	iface       string
	disableWait bool
	skipOOO     bool
	skipMTU     int
	outBpf      string
	reorder     bool
}

/*
NewHandle creates a new Handle object and conducts pre-flight setup for pcap replay
*/
func NewHandle(c Config) (*Handle, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	h := &Handle{
		FileSet:     c.Set,
		iface:       c.WriteInterface,
		outBpf:      c.OutBpf,
		disableWait: c.DisableWait,
		skipOOO:     c.SkipOutOfOrder,
		skipMTU:     c.SkipMTU,
		reorder:     c.Reorder,
	}
	if c.FilterRegex != nil {
		logrus.Info("Filtering pcap files")
		if err := h.FileSet.FilterFilesByRegex(c.FilterRegex); err != nil {
			return h, err
		}
	}
	if !c.TimeFrom.IsZero() {
		logrus.Infof("Filtering pcap files to adjust replay beginning %s", c.TimeFrom)
		if err := h.FileSet.FilterFilesByTime(c.TimeFrom, true); err != nil {
			return h, err
		}
	}
	if !c.TimeTo.IsZero() {
		logrus.Infof("Filtering pcap files to adjust replay end %s", c.TimeTo)
		if err := h.FileSet.FilterFilesByTime(c.TimeTo, false); err != nil {
			return h, err
		}
	}
	if err := h.FileSet.UpdateDelay(); err != nil {
		return nil, err
	}
	if c.ScaleEnabled {
		h.scale = true
		h.speedMod = h.FileSet.Duration().Seconds() / c.ScaleDuration.Seconds()
		for _, item := range h.FileSet.Files {
			item.Delay = item.Delay / time.Duration(h.speedMod)
			item.DelayHuman = item.Delay.String()
		}
		logrus.
			WithField("value", h.speedMod).
			Info("scaling enabled, updated speed modifier")
	} else {
		h.speedMod = 1
	}

	return h, nil
}

// Play starts the replay sequence once Handle object has been constructed
func (h *Handle) Play() error {
	packets := make(chan []byte)

	pool, ctx := errgroup.WithContext(context.Background())
	for _, p := range h.FileSet.Files {
		type params struct {
			Path  string
			Delay time.Duration
			models.Period
		}
		vals := params{
			Path:  p.Path,
			Delay: p.Delay,
			Period: models.Period{
				Beginning: p.Beginning,
				End:       p.End,
			},
		}
		pool.Go(func() error {
			var outOfOrder, count int

			start := time.Now()
			estimate := vals.Period.Duration() / time.Duration(h.speedMod)

			defer func() {
				if !h.disableWait {
					estimate = estimate + vals.Delay
				}
				logrus.WithFields(logrus.Fields{
					"path":           vals.Path,
					"took_actual":    time.Since(start),
					"took_estimated": estimate,
					"out_of_order":   outOfOrder,
					"sent_pkts":      count,
					"delay":          vals.Delay,
				}).Debug("file replay done")
			}()

			fh, err := Open(vals.Path)
			if err != nil {
				return err
			}
			defer fh.Close()
			reader, err := pcapgo.NewReader(fh)
			if err != nil {
				return err
			}

			lctx := logrus.WithFields(logrus.Fields{
				"delay_duration": vals.Delay,
				"delay":          !h.disableWait,
				"pcap":           vals.Path,
				"estimate":       estimate,
				"batch_reorder":  h.reorder,
			})
			lctx.Info("starting replay worker")

			if !h.disableWait {
				time.Sleep(vals.Delay)
				if vals.Delay > 0 {
					lctx.Debug("delay done, playing pcap")
				}
			}

			var fn pktSendFunc

			if h.reorder {
				fn = sendBatchReorder
			} else {
				fn = sendPerPacket
			}

			res, err := fn(vals.Beginning, reader, packets, *h)
			if err != nil {
				return err
			}
			count = res.count
			outOfOrder = res.outOfOrder

			return nil
		})
	}

	writer, err := pcap.OpenLive(h.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer writer.Close()
	if h.outBpf != "" {
		if err := writer.SetBPFFilter(h.outBpf); err != nil {
			return err
		}
	}

	go func() {
		defer close(packets)

		var counter, oversize uint64
		ticker := time.NewTicker(5 * time.Second)
		start := time.Now()

	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-ticker.C:
				logrus.WithFields(logrus.Fields{
					"written":  counter,
					"pps":      int(float64(counter) / time.Since(start).Seconds()),
					"oversize": oversize,
				}).Info("packets written")
			case packet, ok := <-packets:
				if !ok {
					break loop
				}
				if len(packet) > h.skipMTU {
					oversize++
					continue loop
				}
				if err := writer.WritePacketData(packet); err != nil {
					logrus.Error(err)
					break loop
				}
				counter++
			}
		}
	}()

	return pool.Wait()
}

type pktSendFunc func(time.Time, *pcapgo.Reader, chan<- []byte, Handle) (*result, error)

type result struct {
	count      int
	outOfOrder int
}

func sendPerPacket(
	last time.Time,
	reader *pcapgo.Reader,
	packets chan<- []byte,
	h Handle,
) (*result, error) {
	res := &result{}
loop:
	for {
		data, ci, err := reader.ReadPacketData()

		if err != nil && err == io.EOF {
			break loop
		} else if err != nil {
			return res, err
		}

		if ci.Timestamp.Before(last) {
			res.outOfOrder++
			if h.skipOOO {
				continue loop
			}
		}
		delay := ci.Timestamp.Sub(last) / time.Duration(h.speedMod)
		if delay > DelayGrace && !ci.Timestamp.Before(last) {
			time.Sleep(delay)
		}
		packets <- data
		last = ci.Timestamp
		res.count++
	}
	return res, nil
}

func sendBatchReorder(
	last time.Time,
	reader *pcapgo.Reader,
	packets chan<- []byte,
	h Handle,
) (*result, error) {
	res := &result{}
	b := make(pBuf, 0, 100)

loop:
	for {
		data, ci, err := reader.ReadPacketData()

		if err != nil && err == io.EOF {
			break loop
		} else if err != nil {
			return res, err
		}

		b = append(b, packet{
			Timestamp: ci.Timestamp,
			Payload:   data,
		})

		if res.count%100 == 0 {
			last = sendPackets(b, packets, int64(h.speedMod), h.scale, last)
			b = make(pBuf, 0, 100)
		}
		res.count++
	}
	return res, nil
}

type pBuf []packet

type packet struct {
	Payload   []byte
	Timestamp time.Time
}

func sendPackets(
	b pBuf,
	tx chan<- []byte,
	mod int64,
	scale bool,
	prevLast time.Time,
) (last time.Time) {

	sort.Slice(b, func(i, j int) bool {
		return b[i].Timestamp.Before(b[j].Timestamp)
	})

	last = prevLast
	for _, pkt := range b {
		delay := pkt.Timestamp.Sub(last) / time.Duration(mod)
		if delay > DelayGrace {
			time.Sleep(delay)
		}
		tx <- pkt.Payload
		last = pkt.Timestamp
	}
	return last
}
