package replay

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"gopherCap/pkg/pcapset"

	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

/*
Config is used for passing Handle configurations when creating a new replay object
*/
type Config struct {
	Set            pcapset.Set
	WriteInterface string
	FilterRegex    *regexp.Regexp
	SpeedModifier  float64
	OutBpf         string

	TimeFrom, TimeTo time.Time
}

/*
Validate implements a standard interface for checking config struct validity and setting
sane default values.
*/
func (c Config) Validate() error {
	if err := c.Set.Validate(); err != nil {
		return err
	}
	if c.SpeedModifier < 0 {
		return fmt.Errorf("Invalid speed modifier %.2f - should be positive value", c.SpeedModifier)
	}
	return nil
}

/*
Handle is the core object managing replay state
*/
type Handle struct {
	FileSet pcapset.Set

	speedMod float64
	iface    string

	packets chan []byte
	errs    chan error

	outBpf string

	writer *pcap.Handle

	wg *sync.WaitGroup
}

/*
NewHandle creates a new Handle object and conducts pre-flight setup for pcap replay
*/
func NewHandle(c Config) (*Handle, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	h := &Handle{
		FileSet: c.Set,
		wg:      &sync.WaitGroup{},
		packets: make(chan []byte, len(c.Set.Files)),
		errs:    make(chan error, len(c.Set.Files)),
		iface:   c.WriteInterface,
		outBpf:  c.OutBpf,
		speedMod: func() float64 {
			if c.SpeedModifier > 0 {
				return c.SpeedModifier
			}
			return 1.0
		}(),
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
	for _, p := range h.FileSet.Files {
		h.wg.Add(1)
		go replayReadWorker(h.wg, p, h.packets, h.errs, h.speedMod)
	}
	go func() {
		h.wg.Wait()
		close(h.packets)
	}()
	return h, nil
}

// Play starts the replay sequence once Handle object has been constructed
func (h *Handle) Play(ctx context.Context) error {
	if h.writer == nil {
		writer, err := pcap.OpenLive(h.iface, 65536, true, pcap.BlockForever)
		if err != nil {
			return err
		}
		h.writer = writer
	}
	defer h.writer.Close()
	if err := h.writer.SetBPFFilter(h.outBpf); err != nil {
		return err
	}
	var counter, lastCount uint64
	ticker := time.NewTicker(1 * time.Second)

loop:
	for {
		select {
		case <-ticker.C:
			logrus.Infof("Written %d packets %d PPS", counter, counter-lastCount)
			lastCount = counter
		case packet, ok := <-h.packets:
			if !ok {
				break loop
			}
			if err := h.writer.WritePacketData(packet); err != nil {
				return err
			}
			counter++
		}
	}
	return nil
}

// Errors is used to extract async worker exit issues
func (h Handle) Errors() <-chan error {
	return h.errs
}
