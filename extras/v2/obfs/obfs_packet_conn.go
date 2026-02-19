package obfs

import (
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	udpBufferSize = 32768
)
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, udpBufferSize)
	},
}


type ObfsStats struct {
	PacketsReceived  uint64
	PacketsSent      uint64
	PacketsDropped   uint64
	BytesReceived    uint64
	BytesSent        uint64
	DeobfsFailures   uint64
}

type obfsPacketConn struct {
	Conn     net.PacketConn
	Obfs     Obfuscator
	Stats    ObfsStats
	readBuf  []byte
	writeBuf []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex
	closed   uint32
}

type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn *net.UDPConn
}

func WrapPacketConn(conn net.PacketConn, obfs Obfuscator) net.PacketConn {
	opc := &obfsPacketConn{
		Conn:    conn,
		Obfs:    obfs,
		readBuf: make([]byte, udpBufferSize),
	}
	if udpConn, ok := conn.(*net.UDPConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: opc,
			UDPConn:        udpConn,
		}
	}
	return opc
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
    if atomic.LoadUint32(&c.closed) == 1 {
        return 0, nil, net.ErrClosed
    }

    c.readMu.Lock()
    defer c.readMu.Unlock()

    for {
        if atomic.LoadUint32(&c.closed) == 1 {
            return 0, nil, net.ErrClosed
        }

        // Увеличиваем буфер для входящих пакетов
        requiredSize := len(p) + 20
        if cap(c.readBuf) < requiredSize {
            c.readBuf = make([]byte, requiredSize)
        } else {
            c.readBuf = c.readBuf[:requiredSize]
        }

        n, addr, err = c.Conn.ReadFrom(c.readBuf)
        if n <= 0 {
            return n, addr, err
        }

        nn := c.Obfs.Deobfuscate(c.readBuf[:n], p)
        if nn > 0 {
            atomic.AddUint64(&c.Stats.PacketsReceived, 1)
            atomic.AddUint64(&c.Stats.BytesReceived, uint64(nn))
            return nn, addr, nil
        }

        // Добавляем лог для отладки
        fmt.Printf("[OBFS] Deobfuscate failed for %d bytes\n", n)
        atomic.AddUint64(&c.Stats.DeobfsFailures, 1)
        atomic.AddUint64(&c.Stats.PacketsDropped, 1)

        if err != nil {
            return 0, addr, err
        }
    }
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
    if atomic.LoadUint32(&c.closed) == 1 {
        return 0, net.ErrClosed
    }

    c.writeMu.Lock()
    defer c.writeMu.Unlock()

    // ВАЖНО: Увеличиваем буфер на 20 байт для VEX3
    requiredSize := len(p) + 20  // vex3SeqLen + vex3MacLen
    tempBuf := bufferPool.Get().([]byte)

    // Убедимся что буфер достаточно большой
    if cap(tempBuf) < requiredSize {
        tempBuf = make([]byte, requiredSize)
    } else {
        tempBuf = tempBuf[:requiredSize]
    }
    defer bufferPool.Put(tempBuf)

    nn := c.Obfs.Obfuscate(p, tempBuf)
    if nn == 0 {
        // Добавляем лог для отладки
        fmt.Printf("[OBFS] Obfuscate failed for %d bytes (need %d)\n", len(p), requiredSize)
        return 0, errors.New("obfuscation failed")
    }

    _, err = c.Conn.WriteTo(tempBuf[:nn], addr)
    if err == nil {
        n = len(p)
        atomic.AddUint64(&c.Stats.PacketsSent, 1)
        atomic.AddUint64(&c.Stats.BytesSent, uint64(n))
    }

    return n, err
}

func (c *obfsPacketConn) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return c.Conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *obfsPacketConn) GetStats() ObfsStats {
	return ObfsStats{
		PacketsReceived: atomic.LoadUint64(&c.Stats.PacketsReceived),
		PacketsSent:     atomic.LoadUint64(&c.Stats.PacketsSent),
		PacketsDropped:  atomic.LoadUint64(&c.Stats.PacketsDropped),
		BytesReceived:   atomic.LoadUint64(&c.Stats.BytesReceived),
		BytesSent:       atomic.LoadUint64(&c.Stats.BytesSent),
		DeobfsFailures:  atomic.LoadUint64(&c.Stats.DeobfsFailures),
	}
}

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}