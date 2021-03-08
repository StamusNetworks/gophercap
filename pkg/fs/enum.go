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
	"bufio"
	"io"
	"os"
)

/*
Content is enum signifying common file formats
*/
type Content int

const (
	Octet Content = iota
	Plaintext
	Gzip
	Xz
	Bzip
	Utf8
	Utf16
)

/*
Detect file magic without relying on http package
*/

func magic(path string) (Content, error) {
	var (
		err error
		mag []byte
		in  io.ReadCloser
	)
	if in, err = os.Open(path); err != nil {
		return Octet, err
	}
	defer in.Close()

	if mag, err = bufio.NewReader(in).Peek(8); err != nil {
		return Octet, err
	}

	switch {
	case mag[0] == 31 && mag[1] == 139:
		return Gzip, nil
	case mag[0] == 253 && mag[1] == 55 && mag[2] == 122 && mag[3] == 88 && mag[4] == 90 && mag[5] == 0 && mag[6] == 0:
		return Xz, nil
	case mag[0] == 255 && mag[1] == 254:
		return Utf16, nil
	case mag[0] == 239 && mag[1] == 187 && mag[2] == 191:
		return Utf8, nil
	default:
		return Octet, nil
	}
}
