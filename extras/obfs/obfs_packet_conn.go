package obfs

import (
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const udpBufferSize = 8192

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
	Conn   net.PacketConn
	Obfs   Obfuscator
	Stats  ObfsStats

	readBuf    []byte
	writeBuf   []byte
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     uint32
}

type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn *net.UDPConn
}

func WrapPacketConn(conn net.PacketConn, obfs Obfuscator) net.PacketConn {
	opc := &obfsPacketConn{
		Conn:     conn,
		Obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
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

	tempBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(tempBuf)

	for {
		if atomic.LoadUint32(&c.closed) == 1 {
			return 0, nil, net.ErrClosed
		}

		c.readMutex.Lock()
		n, addr, err = c.Conn.ReadFrom(tempBuf)
		c.readMutex.Unlock()

		if n <= 0 {
			return n, addr, err
		}

		atomic.AddUint64(&c.Stats.PacketsReceived, 1)
		atomic.AddUint64(&c.Stats.BytesReceived, uint64(n))

		nn := c.Obfs.Deobfuscate(tempBuf[:n], p)
		if nn > 0 {
			atomic.AddUint64(&c.Stats.PacketsSent, 1)
			atomic.AddUint64(&c.Stats.BytesSent, uint64(nn))
			return nn, addr, nil
		}

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

	tempBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(tempBuf)

	c.writeMutex.Lock()
	nn := c.Obfs.Obfuscate(p, tempBuf)
	if nn > 0 {
		_, err = c.Conn.WriteTo(tempBuf[:nn], addr)
	}
	c.writeMutex.Unlock()

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