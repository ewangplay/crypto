package cipher_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ewangplay/crypto/cipher"
	"github.com/ewangplay/crypto/sm4"
)

func TestECBEncrypterSM4(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("691473fa1272984c6ee72084a497da9cf25e8006f61aeaccc4f6e6c27eb0d1becae5eeee7543e59d075c8743fadc93d9")

	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	encrypter := cipher.NewECBEncrypter(c)

	src := pkcs7Padding(plaintext)

	data := make([]byte, len(src))
	copy(data, src)

	encrypter.CryptBlocks(data, data)
	if !bytes.Equal(data, ciphertext) {
		t.Errorf("ECBEncrypter\nhave %x\nwant %x", data, ciphertext)
	}
}

func TestECBDecrypterSM4(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("691473fa1272984c6ee72084a497da9cf25e8006f61aeaccc4f6e6c27eb0d1becae5eeee7543e59d075c8743fadc93d9")

	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	decrypter := cipher.NewECBDecrypter(c)

	data := make([]byte, len(ciphertext))
	copy(data, ciphertext)

	decrypter.CryptBlocks(data, data)
	dst, err := pkcs7UnPadding(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst, plaintext) {
		t.Errorf("ECBDecrypter\nhave %x\nwant %x", dst, plaintext)
	}
}

func pkcs7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > sm4.BlockSize || unpadding == 0)")
	}

	pad := src[(length - unpadding):]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}
