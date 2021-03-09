/*
Copyright © 2021 Stamus Networks oss@stamus-networks.com

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
package extract

import (
	"errors"
	"io/ioutil"
	"path"
	"regexp"
	"strconv"
	"strings"
	"github.com/sirupsen/logrus"
)


type PcapFileList struct {
	Files []string
	dname string
	fname string
	index int
	file_parsing *regexp.Regexp
	thread_index int
	timestamp_index int
}

/* Suricata supports following expansion
- %n -- thread number
- %i -- thread id
- %t -- timestamp
*/
func (pl *PcapFileList) buildPcapNameParsing(file_format string) {
	/* get each token */
	thread_index := strings.Index(file_format, "%n")
	if thread_index == -1 {
		thread_index = strings.Index(file_format, "%i")
	}
	timestamp_index := strings.Index(file_format, "%t")
	if thread_index < timestamp_index {
		pl.thread_index = 1
		pl.timestamp_index = 2
	} else {
		pl.thread_index = 2
		pl.timestamp_index = 1
	}
	/* handle the case where just the timestamp is available */
	if thread_index == -1 {
		pl.thread_index = -1
		pl.timestamp_index = 1
	}
	regexp_string := strings.Replace(file_format, "%n", `(\d+)`, 1)
	regexp_string = strings.Replace(regexp_string, "%i", `(\d+)`, 1)
	regexp_string = strings.Replace(regexp_string, "%t", `(\d+)`, 1)
	logrus.Debug("Using regexp: ", regexp_string)
	/* build regular expression */
	pl.file_parsing = regexp.MustCompile(regexp_string)
}

func NewPcapFileList(dname string, event Event, file_format string) *PcapFileList {
	pl := new(PcapFileList)
	pl.dname = dname
	pl.buildPcapNameParsing(file_format)
	if len(event.Capture_file) > 0 {
		full_name := path.Join(dname, event.Capture_file)
		pl.Files = append(pl.Files, full_name)
		err := pl.buildPcapList()
		if err != nil {
			return nil
		}
		pl.fname = event.Capture_file
	} else {
		logrus.Debug("Scanning will start soon")
		err := pl.buildFullPcapList()
		if err != nil {
			return nil
		}
	}
	return pl
}

func (pl *PcapFileList) GetNext() (string, error) {
	if pl.index < len(pl.Files) {
		pfile := pl.Files[pl.index]
		pl.index += 1
		return pfile, nil
	}
	return "", errors.New("No more file")
}

func (pl *PcapFileList) buildPcapList() error {
	dname := path.Dir(pl.Files[0])
	logrus.Debug("Scanning directory: ", dname)
	file_part := path.Base(pl.Files[0])
	match := pl.file_parsing.FindStringSubmatch(file_part)
	if len(match) == 0 {
		logrus.Errorf("file %v does not match file format", file_part)
		return errors.New("Invalid file name in event")
	}
	var thread_index int64 = -1
	if (pl.thread_index != -1) {
		thread_index, _ = strconv.ParseInt(match[pl.thread_index], 10, 64)
	}
	timestamp, err := strconv.ParseInt(match[pl.timestamp_index], 10, 64)
	files, err := ioutil.ReadDir(dname)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", dname, err)
	}
	for _, file := range files {
		if file.Name() == file_part {
			continue
		}
		l_match := pl.file_parsing.FindStringSubmatch(file.Name())
		if l_match == nil {
			continue
		}
		if pl.thread_index != -1 {
			l_thread_index, err := strconv.ParseInt(l_match[pl.thread_index], 10, 64)
			if err != nil {
				logrus.Warning("Can't parse integer")
			}
			if l_thread_index != thread_index {
				continue
			}
		}
		l_timestamp, err := strconv.ParseInt(l_match[pl.timestamp_index], 10, 64)
		if err != nil {
			logrus.Warning("Can't parse integer")
		}
		if l_timestamp > timestamp {
			logrus.Infof("Adding file %v", file.Name())
			pl.Files = append(pl.Files, path.Join(dname, file.Name()))
		} else {
			logrus.Debugf("Skipping file %v", file.Name())
		}
	}
	return nil
}

func (pl *PcapFileList) buildFullPcapList() error {
	logrus.Debugf("Scanning directory: %v", pl.dname)
	files, err := ioutil.ReadDir(pl.dname)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", pl.dname, err)
		return errors.New("Can't open directory")
	}
	for _, file := range files {
		l_match := pl.file_parsing.FindStringSubmatch(file.Name())
		if l_match == nil {
			continue
		}
		logrus.Infof("Adding file %v", file.Name())
		pl.Files = append(pl.Files, path.Join(pl.dname, file.Name()))
	}
	return nil
}


