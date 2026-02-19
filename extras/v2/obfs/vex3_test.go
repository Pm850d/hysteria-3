package obfs

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVex3Obfuscator(t *testing.T) {
	o, err := NewVex3Obfuscator([]byte("average_password"))
	require.NoError(t, err)

	in := make([]byte, 1200)
	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)

	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(in)

		n := o.Obfuscate(in, oOut)
		assert.Greater(t, n, 0, "obfuscate failed")

		n = o.Deobfuscate(oOut[:n], dOut)
		assert.Equal(t, in, dOut[:n], "deobfuscate mismatch")
	}
}

func TestVex3DifferentSizes(t *testing.T) {
	o, err := NewVex3Obfuscator([]byte("test_key_123"))
	require.NoError(t, err)

	sizes := []int{64, 512, 1200, 1400, 4096}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			in := make([]byte, size)
			_, _ = rand.Read(in)

			oOut := make([]byte, size+64)
			dOut := make([]byte, size+64)

			n := o.Obfuscate(in, oOut)
			assert.Greater(t, n, 0)

			n = o.Deobfuscate(oOut[:n], dOut)
			assert.Equal(t, in, dOut[:n])
		})
	}
}

func TestVex3ShortKey(t *testing.T) {
	_, err := NewVex3Obfuscator([]byte("abc"))
	assert.Error(t, err)
}

func BenchmarkVex3_Obfuscate(b *testing.B) {
	o, _ := NewVex3Obfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Obfuscate(in, out)
	}
}

func BenchmarkVex3_Deobfuscate(b *testing.B) {
	o, _ := NewVex3Obfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)

	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)

	o.Obfuscate(in, oOut)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		o.Deobfuscate(oOut, dOut)
	}
}

func BenchmarkVex3_RoundTrip(b *testing.B) {
	o, _ := NewVex3Obfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)

	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := o.Obfuscate(in, oOut)
		o.Deobfuscate(oOut[:n], dOut)
	}
}