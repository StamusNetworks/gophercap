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
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type PcapFileList struct {
	Files          []string
	DirName        string
	FileName       string
	Index          int
	FileParsing    *regexp.Regexp
	ThreadIndex    int
	TimestampIndex int
}

/* Suricata supports following expansion
- %n -- thread number
- %i -- thread id
- %t -- timestamp
*/
func (pl *PcapFileList) buildPcapNameParsing(fileFormat string) {
	/* get each token */
	threadIndex := strings.Index(fileFormat, "%n")
	if threadIndex == -1 {
		threadIndex = strings.Index(fileFormat, "%i")
	}
	timestampIndex := strings.Index(fileFormat, "%t")
	if threadIndex < timestampIndex {
		pl.ThreadIndex = 1
		pl.TimestampIndex = 2
	} else {
		pl.ThreadIndex = 2
		pl.TimestampIndex = 1
	}
	/* handle the case where just the timestamp is available */
	if threadIndex == -1 {
		pl.ThreadIndex = -1
		pl.TimestampIndex = 1
	}
	regexpString := strings.Replace(fileFormat, "%n", `(\d+)`, 1)
	regexpString = strings.Replace(regexpString, "%i", `(\d+)`, 1)
	regexpString = strings.Replace(regexpString, "%t", `(\d+)`, 1)
	logrus.Debug("Using regexp: ", regexpString)
	/* build regular expression */
	pl.FileParsing = regexp.MustCompile(regexpString)
}

func NewPcapFileList(dname string, event Event, fileFormat string) *PcapFileList {
	pl := new(PcapFileList)
	pl.DirName = dname
	pl.buildPcapNameParsing(fileFormat)
	if len(event.CaptureFile) > 0 {
		fullName := path.Join(dname, event.CaptureFile)
		pl.Files = append(pl.Files, fullName)
		err := pl.buildPcapList()
		if err != nil {
			return nil
		}
		pl.FileName = event.CaptureFile
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
	if pl.Index < len(pl.Files) {
		pfile := pl.Files[pl.Index]
		pl.Index += 1
		return pfile, nil
	}
	return "", errors.New("No more file")
}

func (pl *PcapFileList) buildPcapList() error {
	dName := path.Dir(pl.Files[0])
	logrus.Debug("Scanning directory: ", dName)
	filePart := path.Base(pl.Files[0])
	match := pl.FileParsing.FindStringSubmatch(filePart)
	if len(match) == 0 {
		logrus.Errorf("file %v does not match file format", filePart)
		return errors.New("Invalid file name in event")
	}
	var threadIndex int64 = -1
	if pl.ThreadIndex != -1 {
		threadIndex, _ = strconv.ParseInt(match[pl.ThreadIndex], 10, 64)
	}
	timestamp, err := strconv.ParseInt(match[pl.TimestampIndex], 10, 64)
	files, err := ioutil.ReadDir(dName)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", dName, err)
	}
	for _, file := range files {
		if file.Name() == filePart {
			continue
		}
		lMatch := pl.FileParsing.FindStringSubmatch(file.Name())
		if lMatch == nil {
			continue
		}
		if pl.ThreadIndex != -1 {
			lThreadIndex, err := strconv.ParseInt(lMatch[pl.ThreadIndex], 10, 64)
			if err != nil {
				logrus.Warning("Can't parse integer")
			}
			if lThreadIndex != threadIndex {
				continue
			}
		}
		lTimestamp, err := strconv.ParseInt(lMatch[pl.TimestampIndex], 10, 64)
		if err != nil {
			logrus.Warning("Can't parse integer")
		}
		if lTimestamp > timestamp {
			logrus.Infof("Adding file %v", file.Name())
			pl.Files = append(pl.Files, path.Join(dName, file.Name()))
		} else {
			logrus.Debugf("Skipping file %v", file.Name())
		}
	}
	return nil
}

func (pl *PcapFileList) buildFullPcapList() error {
	logrus.Debugf("Scanning directory: %v", pl.DirName)
	files, err := ioutil.ReadDir(pl.DirName)
	if err != nil {
		logrus.Warningf("Can't open directory %v: %v", pl.DirName, err)
		return errors.New("Can't open directory")
	}
	for _, file := range files {
		lMatch := pl.FileParsing.FindStringSubmatch(file.Name())
		if lMatch == nil {
			continue
		}
		logrus.Infof("Adding file %v", file.Name())
		pl.Files = append(pl.Files, path.Join(pl.DirName, file.Name()))
	}
	return nil
}
