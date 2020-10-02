/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
