package fs

import (
	"io"
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
	rx := FilePathWalkDir(root, suffix)
	tx := make([]Pcap, 0)
	for p := range rx {
		tx = append(tx, p)
	}
	return tx, nil
}
