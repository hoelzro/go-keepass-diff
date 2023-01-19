package main

import (
	"io"
)

type keepassV4Decryptor struct{}

func (v4 *keepassV4Decryptor) Decrypt(r io.Reader, password string) (*KeePassFile, error) {
	panic("NYI")
}
