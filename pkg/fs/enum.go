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
