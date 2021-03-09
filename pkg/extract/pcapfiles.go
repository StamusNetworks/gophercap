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
	"github.com/sirupsen/logrus"
)


type PcapFileList struct {
	Files []string
	dname string
	fname string
	index int
}

func NewPcapFileList(dname string, event Event) *PcapFileList {
	pl := new(PcapFileList)
	pl.dname = dname
	if len(event.Capture_file) > 0 {
		full_name := path.Join(dname, event.Capture_file)
		pl.Files = append(pl.Files, full_name)
		pl.buildPcapList()
		pl.fname = event.Capture_file
	} else {
		logrus.Debug("Scanning will start soon")
		pl.buildFullPcapList()
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

func (pl *PcapFileList) buildPcapList() string {
	logrus.Debug("Scanning directory")
	dname := path.Dir(pl.Files[0])
	file_part := path.Base(pl.Files[0])
	re := regexp.MustCompile(`.*-(\d+)-(\d+).*pcap`)
	match := re.FindStringSubmatch(file_part)
	thread_index, err := strconv.ParseInt(match[1], 10, 64)
	timestamp, err := strconv.ParseInt(match[2], 10, 64)
	logrus.Debugf("File on thread %v with timestamp %v", thread_index, timestamp)
	files, err := ioutil.ReadDir(dname)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", dname, err)
	}
	for _, file := range files {
		if file.Name() == file_part {
			continue
		}
		l_match := re.FindStringSubmatch(file.Name())
		if l_match == nil {
			continue
		}
		l_thread_index, err := strconv.ParseInt(l_match[1], 10, 64)
		if err != nil {
			logrus.Warning("Can't parse integer")
		}
		l_timestamp, err := strconv.ParseInt(l_match[2], 10, 64)
		if err != nil {
			logrus.Warning("Can't parse integer")
		}
		if l_thread_index != thread_index {
			continue
		}
		if l_timestamp > timestamp {
			logrus.Infof("Adding file %v", file.Name())
			pl.Files = append(pl.Files, path.Join(dname, file.Name()))
		} else {
			logrus.Debugf("Skipping file %v", file.Name())
		}
	}
	return "" //path.Join(next_name)
}

func (pl *PcapFileList) buildFullPcapList() string {
	logrus.Debugf("Scanning directory: %v", pl.dname)
	re := regexp.MustCompile(`.*-(\d+)-(\d+).*pcap`)
	files, err := ioutil.ReadDir(pl.dname)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", pl.dname, err)
	}
	for _, file := range files {
		l_match := re.FindStringSubmatch(file.Name())
		if l_match == nil {
			continue
		}
		logrus.Infof("Adding file %v", file.Name())
		pl.Files = append(pl.Files, path.Join(pl.dname, file.Name()))
	}
	return "" //path.Join(next_name)
}


