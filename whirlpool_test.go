package whirlpool

import (
	"fmt"
	"testing"
	"time"
)

func TestWhirlpool(t *testing.T) {
	// "a"
	hash := "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
	w := New()
	w.Write([]byte("a"))
	calcHash := fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X\n", w.Sum(nil))
		fmt.Printf("a checksums not equal")
	} else {
		fmt.Printf("a ok\n")
	}

	// ""
	hash = "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"
	w.Reset()
	w.Write([]byte(""))
	calcHash = fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X\n", w.Sum(nil))
		fmt.Printf("\"\" checksums not equal")
	} else {
		fmt.Printf("\"\" ok\n")
	}

	// "message digest"
	hash = "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E"
	//w.Reset()
	w.Write([]byte("message digest"))
	calcHash = fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X\n", w.Sum(nil))
		fmt.Printf("message digest checksums not equal")
	} else {
		fmt.Printf("message digest ok\n")
	}

	// "abcdefghijklmnopqrstuvwxyz"
	hash = "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B"
	w.Reset()
	w.Write([]byte("abcdefghijklmnopqrstuvwxyz"))
	calcHash = fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X\n", w.Sum(nil))
		fmt.Printf("abcdefghijklmnopqrstuvwxyz checksums not equal")
	} else {
		fmt.Printf("abc ok\n")
	}

	// abc123
	hash = "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467"
	w.Reset()
	w.Write([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
	calcHash = fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X\n", w.Sum(nil))
		fmt.Printf("abc123 checksums not equal")
	} else {
		fmt.Printf("abc123 ok\n")
	}
}
