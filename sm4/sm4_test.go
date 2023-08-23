package sm4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSM4(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 16)
	copy(b, src)

	c.Encrypt(b, b)

	fmt.Printf("%s\n", hex.EncodeToString(b))
	// Output: 681edf34d206965e86b3e94f536e4246

	c.Decrypt(b, b)

	if bytes.Compare(b, src) != 0 {
		t.Fatal("The original data should be equal to the decrypted data")
	}
}

func TestSM4Loop(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 16)
	copy(b, src)

	for i := 0; i < 1000000; i++ {
		c.Encrypt(b, b)
	}

	fmt.Printf("%s\n", hex.EncodeToString(b))
	// Output: 595298c7c6fd271f0402f804c33d3f66

	for i := 0; i < 1000000; i++ {
		c.Decrypt(b, b)
	}

	if bytes.Compare(b, src) != 0 {
		t.Fatal("The original data should be equal to the decrypted data")
	}
}

func BenchmarkSM4(t *testing.B) {
	t.ReportAllocs()

	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 16)
	copy(b, src)

	for i := 0; i < t.N; i++ {
		c.Encrypt(b, b)
		c.Decrypt(b, b)
	}
}
