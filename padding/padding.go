package padding

import (
	"bytes"
	"errors"
)

type Padding interface {
	Pad(data []byte) ([]byte, error)
	UnPad(data []byte) ([]byte, error)
}

type padding struct {
	blockSize int
}

func newPadding(blockSize int) *padding {
	return &padding{blockSize: blockSize}
}

func NewPkcs5Padding() Padding {
	return newPadding(8)
}

func NewPkcs7Padding(blockSize int) Padding {
	return newPadding(blockSize)
}

func (p *padding) Pad(data []byte) ([]byte, error) {
	padding := p.blockSize - len(data)%p.blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...), nil
}

func (p *padding) UnPad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid data size")
	}

	unpadding := int(data[length-1])

	if unpadding > p.blockSize || unpadding == 0 {
		return nil, errors.New("invalid padding")
	}

	pad := data[(length - unpadding):]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:(length - unpadding)], nil
}
