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
package fs

import (
	"errors"
	"fmt"
	"io"
	"os"
)

/*
WorkerFunc defines an IO task that should be performed on pcap handler, while handler
will take care of opening the right reader (regular, gzip) and properly closing it. Thus
making the externally IO worker agnostic to compression.
*/
type WorkerFunc func(io.Reader) error

/*
NewPcapList creates a new list of pcap files by recursively walking a root directory.
Optional suffix can be used to filter only interesting files. Such as compressed files
with pcap.gz suffix.
*/
func NewPcapList(root, suffix string) ([]Pcap, error) {
	if root == "" {
		return nil, errors.New("Empty root folder for PCAP source")
	}
	fi, err := os.Stat(root)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("PCAP root folder %s does not exist", root)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("PCAP root %s should be a folder", root)
	}
	rx := FilePathWalkDir(root, suffix)
	tx := make([]Pcap, 0)
	for p := range rx {
		tx = append(tx, p)
	}
	return tx, nil
}
