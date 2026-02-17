package obfs

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
)

type mockObfuscator struct {
	obfuscateFail   bool
	deobfuscateFail bool
}

func (m *mockObfuscator) Obfuscate(in, out []byte) int {
	if m.obfuscateFail {
		return 0
	}
	copy(out, in)
	return len(in)
}

func (m *mockObfuscator) Deobfuscate(in, out []byte) int {
	if m.deobfuscateFail {
		return 0
	}
	copy(out, in)
	return len(in)
}

func TestObfsPacketConn_ReadWrite(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	obfs := &mockObfuscator{}
	wrapped := WrapPacketConn(conn, obfs)
	defer wrapped.Close()

	data := make([]byte, 100)
	rand.Read(data)

	go func() {
		time.Sleep(10 * time.Millisecond)
		client, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		defer client.Close()
		client.Write(data)
	}()

	buf := make([]byte, 1024)
	n, _, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes, got %d", len(data), n)
	}

	var stats ObfsStats
	if opc, ok := wrapped.(*obfsPacketConnUDP); ok {
		stats = opc.obfsPacketConn.GetStats()
	} else if opc, ok := wrapped.(*obfsPacketConn); ok {
		stats = opc.GetStats()
	}

	if stats.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", stats.PacketsReceived)
	}
}

func TestObfsPacketConn_Stats(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	obfs := &mockObfuscator{}
	wrapped := WrapPacketConn(conn, obfs)
	defer wrapped.Close()

	var stats ObfsStats
	if opc, ok := wrapped.(*obfsPacketConnUDP); ok {
		stats = opc.obfsPacketConn.GetStats()
	} else if opc, ok := wrapped.(*obfsPacketConn); ok {
		stats = opc.GetStats()
	}

	if stats.PacketsReceived != 0 {
		t.Errorf("Expected 0 packets, got %d", stats.PacketsReceived)
	}
}

func TestObfsPacketConn_Close(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	obfs := &mockObfuscator{}
	wrapped := WrapPacketConn(conn, obfs)

	wrapped.Close()

	buf := make([]byte, 1024)
	_, _, err = wrapped.ReadFrom(buf)
	if err == nil {
		t.Error("Expected error after close")
	}
}

func BenchmarkObfsPacketConn_WriteTo(b *testing.B) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	obfs := &mockObfuscator{}
	wrapped := WrapPacketConn(conn, obfs)
	defer wrapped.Close()

	data := make([]byte, 1200)
	rand.Read(data)
	addr := conn.LocalAddr()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wrapped.WriteTo(data, addr)
	}
}