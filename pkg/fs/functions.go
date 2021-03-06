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
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

/*
FilePathWalkDir walks a root directory recursively, extracting relevant pcap files
*/
func FilePathWalkDir(root, suffix string) <-chan Pcap {
	tx := make(chan Pcap, 0)
	go func() {
		defer close(tx)
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() && strings.HasSuffix(path, suffix) {
				tx <- Pcap{
					Root: root,
					Path: path,
					fi:   info,
				}
			}
			return nil
		})
	}()
	return tx
}

/*
GzipCompress compresses a file with gzip
*/
func GzipCompress(source, target string, remove bool) error {
	reader, err := os.Open(source)
	if err != nil {
		return err
	}

	filename := filepath.Base(source)
	writer, err := os.Create(target)
	if err != nil {
		return err
	}
	defer writer.Close()

	archiver := gzip.NewWriter(writer)
	archiver.Name = filename
	defer archiver.Close()

	if _, err := io.Copy(archiver, reader); err != nil {
		return err
	}
	if !remove {
		return nil
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return nil
}

/*
Open opens a file handle while accounting for compression extracted from file magic
*/
func Open(path string) (io.ReadCloser, error) {
	if path == "" {
		return nil, errors.New("Missing file path")
	}
	m, err := magic(path)
	if err != nil {
		return nil, err
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if m == Gzip {
		gzipHandle, err := gzip.NewReader(handle)
		if err != nil {
			return nil, err
		}
		return gzipHandle, nil
	}
	return handle, nil
}
