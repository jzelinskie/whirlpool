package whirlpool

import (
	"fmt"
	"testing"
)

func TestQBF(t *testing.T) {
	qbf := []byte("a")
	hash := "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
	w := New()
	w.Write(qbf)
	calcHash := fmt.Sprintf("%X", w.Sum(nil))
	if calcHash != hash {
		fmt.Printf("%X", w.Sum(nil))
		panic("checksums not equal")
	}
}
