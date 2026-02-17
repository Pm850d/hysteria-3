package obfs

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVex3Obfuscator(t *testing.T) {
	o, _ := NewVex3Obfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)

	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(in)
		n := o.Obfuscate(in, oOut)
		assert.Greater(t, n, 0)

		n = o.Deobfuscate(oOut[:n], dOut)
		assert.Equal(t, in, dOut[:n])
	}
}

func BenchmarkVex3Obfuscator_Obfuscate(b *testing.B) {
	o, _ := NewVex3Obfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Obfuscate(in, out)
	}
}