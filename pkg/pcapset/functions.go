package pcapset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gopherCap/pkg/fs"
	"gopherCap/pkg/models"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"
)

/*
NewPcapSetFromList instantiates a new Set object from a list of Pcaps from filesystem module.
Used for initial metadata scan.
*/
func NewPcapSetFromList(rx []fs.Pcap, workers int, filePattern string) (*Set, error) {
	if rx == nil || len(rx) == 0 {
		return nil, errors.New("Missing pcap list or empty")
	}
	var (
		fileRegexp *regexp.Regexp
		err        error
	)
	if filePattern != "" {
		fileRegexp, err = regexp.Compile(filePattern)
		if err != nil {
			return nil, fmt.Errorf("Invalid file regexp: %s", err)
		}
	}
	ch, err := concurrentScanPeriods(context.TODO(), rx, workers, fileRegexp)
	if err != nil {
		return nil, err
	}
	s := &Set{Files: make([]Pcap, 0)}
	for f := range ch {
		f.Calculate()
		s.Files = append(s.Files, Pcap{Pcap: f})
	}
	sort.SliceStable(s.Files, func(i, j int) bool {
		return s.Files[i].Beginning.Before(s.Files[j].Beginning)
	})

	s.Period = calculatePeriod(s.Files)
	s.updateDelayValues()

	return s, nil
}

/*
DumpSetJSON writes a Set object to user-defined JSON file
*/
func DumpSetJSON(path string, set Set) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(set)
	if err != nil {
		return err
	}
	f.Write(data)
	return nil
}

/*
LoadSetJSON loads Set object from filesystem JSON dump
*/
func LoadSetJSON(path string) (*Set, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Set
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func calculatePeriod(files []Pcap) models.Period {
	p := &models.Period{}
	for _, f := range files {
		if p.Beginning.IsZero() || f.Beginning.Before(p.Beginning) {
			p.Beginning = f.Beginning
		}
		if p.End.IsZero() || f.End.After(p.End) {
			p.End = f.End
		}
	}
	return *p
}

func concurrentScanPeriods(
	ctx context.Context,
	files []fs.Pcap,
	workers int,
	pattern *regexp.Regexp,
) (<-chan fs.Pcap, error) {
	if files == nil || len(files) == 0 {
		return nil, errors.New("No pcap files")
	}
	if workers < 1 {
		return nil, errors.New("Worker count should be > 0")
	}

	var wg sync.WaitGroup
	rx := make(chan fs.Pcap, 0)
	tx := make(chan fs.Pcap, 0)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int, ctx context.Context) {
			defer wg.Done()
			logrus.Debugf("Started worker %d", id)
			defer logrus.Debugf("Worker %d done", id)

			for pcapfile := range rx {
				if err := pcapfile.ScanPeriod(context.TODO()); err != nil {
					pcapfile.Err = err
				}
				tx <- pcapfile
			}
		}(i, context.TODO())
	}

	go func() {
	loop:
		for i, pcapfile := range files {
			if pattern != nil && !pattern.MatchString(pcapfile.Path) {
				continue loop
			}
			logrus.Debugf("Feeding %s %d/%d", pcapfile.Path, i, len(files))
			rx <- pcapfile
		}
		close(rx)
	}()

	go func() {
		defer close(tx)
		wg.Wait()
	}()

	return tx, nil
}
