package cipher_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ewangplay/crypto/cipher"
	"github.com/ewangplay/crypto/padding"
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
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	src, err := padding.Pad(plaintext)
	if err != nil {
		t.Fatal(err)
	}

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

	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	dst, err := padding.UnPad(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst, plaintext) {
		t.Errorf("ECBDecrypter\nhave %x\nwant %x", dst, plaintext)
	}
}
