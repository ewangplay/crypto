package padding_test

import (
	"fmt"

	"github.com/ewangplay/crypto/padding"
)

func ExamplePadding_Pad() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs5Padding()
	p, err := padding.Pad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D
	// 0A0B0C0D04040404
}

func ExamplePadding_Pad_second() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs5Padding()
	p, err := padding.Pad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D0A0B0C0D
	// 0A0B0C0D0A0B0C0D0808080808080808
}

func ExamplePadding_Pad_third() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(16)
	p, err := padding.Pad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D
	// 0A0B0C0D0C0C0C0C0C0C0C0C0C0C0C0C
}

func ExamplePadding_Pad_forth() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(16)
	p, err := padding.Pad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D0A0B0C0D0A0B0C0D0A0B0C0D
	// 0A0B0C0D0A0B0C0D0A0B0C0D0A0B0C0D10101010101010101010101010101010
}

func ExamplePadding_UnPad() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x04, 0x04, 0x04, 0x04}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs5Padding()
	p, err := padding.UnPad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D04040404
	// 0A0B0C0D
}

func ExamplePadding_UnPad_second() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D,
		0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs5Padding()
	p, err := padding.UnPad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D0A0B0C0D0808080808080808
	// 0A0B0C0D0A0B0C0D
}

func ExamplePadding_UnPad_third() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0C, 0x0C, 0x0C, 0x0C,
		0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(16)
	p, err := padding.UnPad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D0C0C0C0C0C0C0C0C0C0C0C0C
	// 0A0B0C0D
}

func ExamplePadding_UnPad_forth() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D,
		0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D,
		0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
		0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(16)
	p, err := padding.UnPad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%X\n", p)
	// Output:
	// 0A0B0C0D0A0B0C0D0A0B0C0D0A0B0C0D10101010101010101010101010101010
	// 0A0B0C0D0A0B0C0D0A0B0C0D0A0B0C0D
}

func ExamplePadding_UnPad_empty() {
	p := []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(8)
	p, err := padding.UnPad(p)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%v\n", p)
	// Output:
	// 0808080808080808
	// []
}

func ExamplePadding_UnPad_lastzero() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x04, 0x04, 0x04, 0x00}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs5Padding()
	p, err := padding.UnPad(p)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%X\n", p)
	}
	// Output:
	// 0A0B0C0D04040400
	// invalid padding
}

func ExamplePadding_UnPad_invalid() {
	p := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0C, 0x0C, 0x0C, 0x0C,
		0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C}
	fmt.Printf("%X\n", p)
	padding := padding.NewPkcs7Padding(16)
	p, err := padding.UnPad(p)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%X\n", p)
	}
	// Output:
	// 0A0B0C0D0C0C0C0C0C0C0C0C0C0C
	// invalid padding
}
