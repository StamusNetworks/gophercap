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
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"

	"encoding/json"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

const Flow_timeout time.Duration = 600 * 10^9

func writePacket(handle *pcap.Handle, buf []byte) error {
	if err := handle.WritePacketData(buf); err != nil {
		logrus.Warning("Failed to write packet: %s\n", err)
		return err
	}
	return nil
}

type Tunnel struct {
	Src_ip string
	Dest_ip string
	Src_port uint16
	Dest_port uint16
	Proto string
	Depth uint8
}

type Event struct {
	Timestamp string
	Capture_file string
	Src_ip string
	Dest_ip string
	Src_port uint16
	Dest_port uint16
	App_proto string
	Proto string
	Tunnel Tunnel
}

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

func openPcapReaderHandle(fname string, bpf_filter string) (*pcap.Handle, error) {
	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(fname)
	if err != nil {
		return handleRead , err
	}

	if err == nil {
		err = handleRead.SetBPFFilter(bpf_filter)
		if err != nil {
			logrus.Fatal("Invalid BPF Filter: %v", err)
			return handleRead, err
		}
	}
	return handleRead, nil
}


/*
Extract a pcap file for a given flow
*/
func ExtractPcapFile(dname string, oname string, eventdata string, skip_bpf bool) error {
	/* open event file */
	eventfile, err := os.Open(eventdata)
	if err != nil {
		return err
	}
	defer eventfile.Close()

	eventdatastring, err := ioutil.ReadAll(eventfile)
	if err != nil {
		return err
	}

	var event Event
	err = json.Unmarshal(eventdatastring, &event)
	if err != nil {
		return errors.New("Can't parse JSON in " + eventdata)
	}

	if len(event.Capture_file) > 0 {
		filename := path.Join(dname, event.Capture_file)
		_, err := os.Stat(filename)
		if os.IsNotExist(err) {
			logrus.Errorf("File %v does not exist", filename)
			return err
		}
	}

	if event.Tunnel.Depth != 0 {
		logrus.Debugf("Tunnel: %v <-%v-> %v\n", event.Tunnel.Src_ip, event.Tunnel.Proto, event.Tunnel.Dest_ip)
	}
	logrus.Debugf("Flow: %v <-%v:%v-> %v\n", event.Src_ip, event.Proto, event.App_proto, event.Dest_ip)
	IPFlow, transportFlow := builEndpoints(event)

	pcap_file_list := NewPcapFileList(dname, event)

	var bpf_filter string = ""
	if skip_bpf != true {
		bpf_filter, err = buildBPF(event)
		if err != nil {
			logrus.Warning(err)
		}
	}

	// Open up a second pcap handle for packet writes.
	outfile, err := os.Create(oname);
	if err != nil {
		logrus.Fatal("Can't open pcap output file:", err)
		return err
	}
	defer outfile.Close()

	handleWrite := pcapgo.NewWriter(outfile)
	handleWrite.WriteFileHeader(65536, layers.LinkTypeEthernet)  // new file, must do this.
	if err != nil {
		logrus.Fatal("Can't write to output file:", err)
		return err
	}

	start := time.Now()
	pkt := 0
	/* FIXME we can do better here */
	var last_timestamp time.Time = time.Now()
	var first_timestamp time.Time = time.Now()

	fname, err := pcap_file_list.GetNext()
	if err != nil {
		logrus.Debugf("Expected at least one file: %v\n", err)
		return nil
	}
	/*
	Loop over pcap file starting with the one specified in the event
	If timestamp of first packet > last_timestamp of flow + flow_timeout then
	we can consider we are at the last pcap
	*/
	for len(event.Capture_file) == 0 || first_timestamp.Before(last_timestamp.Add(Flow_timeout)) {
		file_pkt := 0
		logrus.Debugf("Reading packets from %s", fname)
		handleRead, err := openPcapReaderHandle(fname, bpf_filter)
		defer handleRead.Close()
		if err != nil {
			logrus.Warningln("This was fast")
			break
		}

		// Loop over packets and write them
		need_break := false
		for {
			data, ci, err := handleRead.ReadPacketData()

			switch {
			case err == io.EOF:
				need_break = true
			case err != nil:
				logrus.Warningf("Failed to read packet %d: %s\n", pkt, err)
			default:
				if skip_bpf == true || event.Tunnel.Depth > 0 {
					if filterTunnel(data, IPFlow, transportFlow, event) {
						handleWrite.WritePacket(ci, data)
						pkt++
						last_timestamp = ci.Timestamp
					}
				} else {
					handleWrite.WritePacket(ci, data)
					pkt++
					file_pkt++
				}
			}
			if need_break {
				logrus.Debugf("Extracted %d packet(s) from pcap file %v", file_pkt, fname)
				break
			}
		}
		/* Open new pcap to see the beginning */
		fname, err = pcap_file_list.GetNext()
		if err != nil {
			logrus.Debugln(err)
			break
		}
		handleTest, err := openPcapReaderHandle(fname, bpf_filter)
		defer handleTest.Close()
		if err != nil {
			break
		}
		_, ci, err := handleRead.ReadPacketData()
		first_timestamp = ci.Timestamp
	}
	logrus.Infof("Finished in %s\n", time.Since(start))
	logrus.Infof("Written %v packet(s)\n", pkt)

	return nil
}
