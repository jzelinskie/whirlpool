package whirlpool

import (
	"fmt"
	"testing"
	"time"
)

func TestQBF(t *testing.T) {
	testString := []byte("a")
	hash := "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
	w := New()
	w.Write(testString)
	calcHash := fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X", w.Sum(nil))
		panic("a checksums not equal")
	}
	w.Reset()
	w.Write([]byte(""))
	hash = "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"
	calcHash = fmt.Sprintf("%X", w.Sum(nil))
	time.Sleep(5000000000)
	if calcHash != hash {
		fmt.Printf("%X", w.Sum(nil))
		panic("qbf checksums not equal")
	}
}
