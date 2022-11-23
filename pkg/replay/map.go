package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/StamusNetworks/gophercap/pkg/models"

	"github.com/sirupsen/logrus"
)

type MapConfig struct {
	Directory string
	Suffix    string
	Pattern   string
	Workers   int
}

/*
NewPcapSetFromList instantiates a new Set object from a list of Pcaps from filesystem module.
Used for initial metadata scan.
*/
func NewPcapSet(c MapConfig) (*PcapSet, error) {
	var (
		fileRegexp *regexp.Regexp
		err        error
	)
	if c.Pattern != "" {
		fileRegexp, err = regexp.Compile(c.Pattern)
		if err != nil {
			return nil, fmt.Errorf("Invalid file regexp: %s", err)
		}
	}
	ch, err := concurrentScanPeriods(
		context.TODO(),
		c.Directory,
		c.Workers,
		fileRegexp,
		c.Suffix,
	)
	if err != nil {
		return nil, err
	}
	s := &PcapSet{Files: make([]*Pcap, 0)}
	for f := range ch {
		s.Files = append(s.Files, f)
	}

	return s, s.UpdateDelay()
}

/*
DumpSetJSON writes a Set object to user-defined JSON file
*/
func DumpSetJSON(path string, set PcapSet) error {
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
func LoadSetJSON(path string) (*PcapSet, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s PcapSet
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func calculatePeriod(files []*Pcap) models.Period {
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
	dir string,
	workers int,
	pattern *regexp.Regexp,
	suffix string,
) (<-chan *Pcap, error) {
	if dir == "" {
		return nil, errors.New("missing source dir")
	}
	if workers < 1 {
		return nil, errors.New("Worker count should be > 0")
	}

	files, err := FindPcapFiles(dir, suffix)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	rx := make(chan string)
	tx := make(chan *Pcap)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int, ctx context.Context) {
			defer wg.Done()
			lctx := logrus.WithField("worker", id)
			lctx.Info("Mapper started")
			defer lctx.Info("Mapper stopped")

		loop:
			for fp := range rx {
				lctx.
					WithField("path", fp).
					Debug("scanning file")
				start := time.Now()
				pf, err := scan(fp, context.TODO())
				if err != nil {
					logrus.
						WithField("file", fp).
						Error(err)
					continue loop
				}
				lctx.
					WithField("took", time.Since(start)).
					WithField("path", fp).
					Info("file mapped")
				tx <- pf
			}
		}(i, context.TODO())
	}

	wg.Add(1)
	go func(fpth string, fsuff string) {
		defer wg.Done()
		defer close(rx)
		for _, f := range files {
			rx <- f
		}
	}(dir, suffix)

	go func() {
		defer close(tx)
		wg.Wait()
	}()

	return tx, nil
}

func FindPcapFiles(dir, suffix string) ([]string, error) {
	tx := make([]string, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, suffix) && err == nil {
			tx = append(tx, path)
		}
		return nil
	})
	return tx, err
}
