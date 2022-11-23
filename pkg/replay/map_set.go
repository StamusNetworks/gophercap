package replay

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/StamusNetworks/gophercap/pkg/models"
)

type PcapSet struct {
	models.Period

	Files []*Pcap `json:"files"`
}

func (s *PcapSet) UpdateDelay() error {
	if len(s.Files) == 0 {
		return errors.New("unable to calculate period, no files")
	}
	s.Period = calculatePeriod(s.Files)

	if s.Beginning.IsZero() || s.End.IsZero() {
		return fmt.Errorf("set global period not initialized")
	}

	for _, item := range s.Files {
		if item.Beginning.IsZero() {
			return fmt.Errorf("missing beginning for %s", item.Path)
		}
		item.Delay = item.Beginning.Sub(s.Beginning)
		item.DelayHuman = item.Delay.String()
	}
	return nil
}

/*
Validate implements a standard interface for checking config struct validity and setting
sane default values.
*/
func (s PcapSet) Validate() error {
	if s.Files == nil || len(s.Files) == 0 {
		return errors.New("Missing pcap files")
	}
	if s.Beginning.IsZero() || s.End.IsZero() {
		return errors.New("Missing set start or end")
	}
	for i, f := range s.Files {
		if f.Beginning.IsZero() || f.End.IsZero() {
			return fmt.Errorf("index %d %+v missing beginning or end ts", i, f)
		}
		if f.Beginning.Before(s.Beginning) {
			return fmt.Errorf("element %d start ts is before global start %s", i, s.Beginning)
		}
		if f.End.After(s.End) {
			return fmt.Errorf("element %d end is after global end %s", i, s.End)
		}
	}
	return nil
}

/*
FilterFilesByRegex subsets pcap Set by applying regexp pattern on file names.
*/
func (s *PcapSet) FilterFilesByRegex(pattern *regexp.Regexp) error {
	if pattern == nil {
		return errors.New("Missing regexp pattern for file filter")
	}
	files := make([]*Pcap, 0)
	for _, f := range s.Files {
		if pattern.MatchString(f.Path) {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return errors.New("Regexp filter removed all files")
	}
	s.Files = files
	return s.UpdateDelay()
}

/*
FilterFilesByTime subsets pcap Set by extracting only files where Period beginning is after or end
is before user-provided timestamp value.
*/
func (s *PcapSet) FilterFilesByTime(ts time.Time, beginning bool) error {
	if ts.After(s.Period.End) {
		return fmt.Errorf("%s is after period end %s", ts, s.Period.End)
	}
	if ts.Before(s.Period.Beginning) {
		return fmt.Errorf("%s is before first period timestamp %s", ts, s.Period.Beginning)
	}
	files := make([]*Pcap, 0)
	for _, f := range s.Files {
		if (beginning && f.Beginning.After(ts)) || (!beginning && f.Beginning.Before(ts)) {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("No files that contain beginning ts %s", ts)
	}
	s.Files = files
	return s.UpdateDelay()
}
