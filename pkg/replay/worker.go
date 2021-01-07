package replay

import (
	"gopherCap/pkg/pcapset"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

/*
replayReadWorker is async goroutine that can only be communicated with via channels
*/
func replayReadWorker(
	wg *sync.WaitGroup,
	pcapfile pcapset.Pcap,
	tx chan<- []byte,
	errs chan<- error,
	modifier float64,
	disableWait bool,
) {
	defer wg.Done()
	fnLoopWithSleep := func(reader *pcapgo.Reader, last time.Time) error {
		for {
			data, ci, err := reader.ReadPacketData()

			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			if ci.Timestamp.After(last) {
				dur := float64(ci.Timestamp.Sub(last)) / modifier
				time.Sleep(time.Duration(dur))
			}
			tx <- data
			last = ci.Timestamp

		}
		return nil
	}
	fn := func(r io.Reader) error {
		reader, err := pcapgo.NewReader(r)
		if err != nil {
			return err
		}

		if !disableWait && pcapfile.Delay > 0 {
			logrus.Infof(
				"file %s start is future, will wait for %s",
				pcapfile.Path,
				time.Duration(int64(float64(pcapfile.Delay)/modifier)),
			)
			dur := float64(pcapfile.Delay) / modifier
			time.Sleep(time.Duration(dur))
		}
		return fnLoopWithSleep(reader, pcapfile.Period.Beginning)
	}
	if err := pcapfile.Do(fn); err != nil && errs != nil {
		errs <- err
	}
	return
}
