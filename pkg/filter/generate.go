/*
Copyright © 2022 Stamus Networks oss@stamus-networks.com

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
package filter

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/StamusNetworks/gophercap/pkg/models"
)

/*
Generate produces a filter YAML configurations from suricata alerts.
*/
func Generate(pth string, parseErrFunc func(error) bool) (YAMLConfig, error) {
	f, err := os.Open(pth)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	tx := make(YAMLConfig)
	flowSet := make(map[int]bool)
	for scanner.Scan() {
		var obj models.EVE
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil && !parseErrFunc(err) {
			return nil, err
		}
		if obj.EventType == "alert" && !flowSet[obj.FlowID] {
			tx[strconv.Itoa(obj.FlowID)] = *filterFromEVE(obj)
			flowSet[obj.FlowID] = true
		}
	}
	if scanner.Err() != nil && scanner.Err() != io.EOF {
		return tx, err
	}
	return tx, nil
}

func filterFromEVE(e models.EVE) *CombinedConfig {
	c := &CombinedConfig{Conditions: make([]FilterItem, 0, 4)}
	c.Conditions = append(c.Conditions, FilterItem{
		Kind:  FilterKindSubnet.String(),
		Match: []string{e.SrcIP.String()},
	})
	c.Conditions = append(c.Conditions, FilterItem{
		Kind:  FilterKindSubnet.String(),
		Match: []string{e.DestIP.String()},
	})
	c.Conditions = append(c.Conditions, FilterItem{
		Kind:  FilterKindPort.String(),
		Match: []string{strconv.Itoa(e.SrcPort)},
	})
	c.Conditions = append(c.Conditions, FilterItem{
		Kind:  FilterKindPort.String(),
		Match: []string{strconv.Itoa(e.DestPort)},
	})
	return c
}
