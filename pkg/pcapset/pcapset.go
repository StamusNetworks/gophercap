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
	"errors"
	"fmt"
	"regexp"
	"time"

	"gopherCap/pkg/models"
)

/*
Set is a container for list of Pcap handles with additional global Period tracking
*/
type Set struct {
	models.Period

	Files []Pcap `json:"files"`
}

/*
Validate implements a standard interface for checking config struct validity and setting
sane default values.
*/
func (s Set) Validate() error {
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

func (s *Set) updateFiles(files []Pcap) *Set {
	s.Files = files
	s.Period = calculatePeriod(files)
	return s.updateDelayValues()
}

func (s *Set) updateDelayValues() *Set {
	for i, p := range s.Files {
		s.Files[i] = p.setDelay(p.Pcap.Period.Delay(s.Period.Beginning))
	}
	return s
}

/*
FilterFilesWithErrs creates a new set listing and removes all files that were not parsed correctly.
*/
func (s *Set) FilterFilesWithErrs() (int, error) {
	files := make([]Pcap, 0)
	var count int
	for _, f := range s.Files {
		if f.Err == nil {
			files = append(files, f)
		} else {
			count++
		}
	}
	if len(files) == 0 {
		return 0, errors.New("No pcap files were parsed successfully")
	}
	s.updateFiles(files)
	return count, nil
}

/*
FilterFilesByRegex subsets pcap Set by applying regexp pattern on file names.
*/
func (s *Set) FilterFilesByRegex(pattern *regexp.Regexp) error {
	if pattern == nil {
		return errors.New("Missing regexp pattern for file filter")
	}
	files := make([]Pcap, 0)
	for _, f := range s.Files {
		if pattern.MatchString(f.Path) {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return errors.New("Regexp filter removed all files")
	}
	s.updateFiles(files)
	return nil
}

/*
FilterFilesByTime subsets pcap Set by extracting only files where Period beginning is after or end
is before user-provided timestamp value.
*/
func (s *Set) FilterFilesByTime(ts time.Time, beginning bool) error {
	if ts.After(s.Period.End) {
		return fmt.Errorf("%s is after period end %s", ts, s.Period.End)
	}
	if ts.Before(s.Period.Beginning) {
		return fmt.Errorf("%s is before first period timestamp %s", ts, s.Period.Beginning)
	}
	files := make([]Pcap, 0)
	for _, f := range s.Files {
		if (beginning && f.Beginning.After(ts)) || (!beginning && f.Beginning.Before(ts)) {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("No files that contain beginning ts %s", ts)
	}
	s.updateFiles(files)
	return nil
}
