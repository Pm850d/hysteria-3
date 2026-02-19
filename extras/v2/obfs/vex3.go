package obfs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

const (
	vex3SeqLen  = 4
	vex3MacLen  = 16
	vex3MinLen  = vex3SeqLen + vex3MacLen
	vex3TimeWin = 2
)

const (
	OpXRot = iota
	OpF1
	OpF2
	OpF3
	OpF4
	OpF5
	OpSwapNibbles
	OpReverseBits
	OpShuffleBits
)

var _ Obfuscator = (*Vex3Obfuscator)(nil)

var ErrVex3KeyTooShort = errors.New("Vex3 key must be at least 4 bytes")
var ErrVex3InvalidPacket = errors.New("Vex3 packet too short or invalid")

var modInverseTable = initModInverseTable()

var sha256Pool = sync.Pool{
	New: func() interface{} { return sha256.New() },
}

// V8 OPT: Пул для параметров
var paramsPool = sync.Pool{
	New: func() interface{} {
		return &Vex3Params{}
	},
}

type Vex3Obfuscator struct {
	Key      []byte
	hmacPool sync.Pool
	state    uint64
	mu       sync.Mutex
}

func NewVex3Obfuscator(key []byte) (*Vex3Obfuscator, error) {
	if len(key) < 4 {
		return nil, ErrVex3KeyTooShort
	}
	nowMin := uint64(time.Now().Unix() / 60)
	o := &Vex3Obfuscator{
		Key: key,
		hmacPool: sync.Pool{
			New: func() interface{} {
				return hmac.New(sha256.New, key)
			},
		},
		state: nowMin << 32,
	}
	return o, nil
}

func (o *Vex3Obfuscator) getSeq() int {
	o.mu.Lock()
	defer o.mu.Unlock()

	oldState := o.state
	lastMin := int64(oldState >> 32)
	seqVal := uint32(oldState & 0xFFFFFFFF)

	nowMin := time.Now().Unix() / 60
	if nowMin != lastMin {
		o.state = uint64(nowMin) << 32
		return 0
	}

	o.state = (uint64(nowMin) << 32) | uint64(seqVal+1)
	return int(seqVal)
}

// V8 OPT: Keystream генератор для шифрования
type keystreamGen struct {
	gen *XorShift128
	buf uint64
	pos int
}

func newKeystreamGen(seed []byte) *keystreamGen {
	return &keystreamGen{
		gen: newXorShift128(seed),
		pos: 8, // Force new random on first call
	}
}

func (k *keystreamGen) nextByte() byte {
	if k.pos >= 8 {
		k.buf = k.gen.Next()
		k.pos = 0
	}
	b := byte((k.buf >> (k.pos * 8)) & 0xFF)
	k.pos++
	return b
}

func (o *Vex3Obfuscator) Obfuscate(in, out []byte) int {
	seq := o.getSeq()
	minute := int(time.Now().Unix() / 60)

	required := vex3SeqLen + len(in) + vex3MacLen
	if len(out) < required {
		return 0
	}

	// Записываем seq
	binary.LittleEndian.PutUint32(out[:vex3SeqLen], uint32(seq))

	// V8 OPT: Генерируем параметры и keystream на лету
	var seedBuf [32]byte
	seedBytes := o.makeSeed(minute, seq, seedBuf[:])
	params := o.generateParams(seedBytes)
	defer paramsPool.Put(params)

	ks := newKeystreamGen(seedBytes)

	// Шифрование с keystream на лету
	for i := 0; i < len(in); i++ {
		v := in[i]
		for _, opCode := range params.OpsCodes {
			v = o.applyOp(v, params, ks, i, opCode)
		}
		out[vex3SeqLen+i] = v
	}

	// MAC вычисляется на header + ciphertext
	var macBuf [16]byte
	o.computeMac(out[:vex3SeqLen+len(in)], minute, seq, macBuf[:])
	copy(out[vex3SeqLen+len(in):], macBuf[:])

	return required
}

func (o *Vex3Obfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < vex3MinLen {
		return 0
	}

	bodyLen := len(in) - vex3SeqLen - vex3MacLen
	if bodyLen < 0 || len(out) < bodyLen {
		return 0
	}

	seq := int(binary.LittleEndian.Uint32(in[:vex3SeqLen]))
	nowMin := int(time.Now().Unix() / 60)

	for offset := -vex3TimeWin; offset <= vex3TimeWin; offset++ {
		tryMin := nowMin + offset

		var expectedMac [16]byte
		o.computeMac(in[:vex3SeqLen+bodyLen], tryMin, seq, expectedMac[:])
		if !hmac.Equal(expectedMac[:], in[vex3SeqLen+bodyLen:]) {
			continue
		}

		decryptedLen := o.decryptBytes(in, tryMin, seq, bodyLen, out)
		if decryptedLen > 0 {
			return decryptedLen
		}
	}

	return 0
}

func (o *Vex3Obfuscator) decryptBytes(data []byte, minute, seq, bodyLen int, out []byte) int {
	var seedBuf [32]byte
	seedBytes := o.makeSeed(minute, seq, seedBuf[:])
	params := o.generateParams(seedBytes)
	defer paramsPool.Put(params)

	ks := newKeystreamGen(seedBytes)

	for i := 0; i < bodyLen; i++ {
		v := data[vex3SeqLen+i]
		for j := len(params.OpsCodes) - 1; j >= 0; j-- {
			v = o.applyOpInv(v, params, ks, i, params.OpsCodes[j])
		}
		out[i] = v
	}

	return bodyLen
}

func (o *Vex3Obfuscator) makeSeed(minute, seq int, out []byte) []byte {
	h := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(h)
	h.Reset()

	h.Write(o.Key)
	h.Write([]byte{'|'})

	var buf [20]byte
	n := binary.PutVarint(buf[:], int64(minute))
	h.Write(buf[:n])
	h.Write([]byte{'|'})
	n = binary.PutVarint(buf[:], int64(seq))
	h.Write(buf[:n])

	return h.Sum(out[:0])
}

func (o *Vex3Obfuscator) computeMac(body []byte, minute, seq int, out []byte) {
	h := o.hmacPool.Get().(hash.Hash)
	defer o.hmacPool.Put(h)
	h.Reset()

	h.Write([]byte{'|'})
	var buf [20]byte
	n := binary.PutVarint(buf[:], int64(minute))
	h.Write(buf[:n])
	h.Write([]byte{'|'})
	n = binary.PutVarint(buf[:], int64(seq))
	h.Write(buf[:n])
	h.Write(body)

	sum := h.Sum(out[:0])
	copy(out, sum[:vex3MacLen])
}

type Vex3Params struct {
	Ops      []string
	OpsCodes []int
	Mask1    uint8
	Mul1     uint8
	Mul1Inv  uint8
	Add1     uint8
	Mask2    uint8
	Shift2   uint8
	Add2     uint8
	Mul3     uint8
	Mul3Inv  uint8
	Add3     uint8
	Mask4    uint8
	Shift5   uint8
	Add5     uint8
	Perm     [8]uint8
	SBox     [256]uint8
	InvSBox  [256]uint8
}

func (o *Vex3Obfuscator) generateParams(seedBytes []byte) *Vex3Params {
	params := paramsPool.Get().(*Vex3Params)
	params.Ops = params.Ops[:0]
	params.OpsCodes = params.OpsCodes[:0]

	// V8 OPT: Генерируем первые 128 байт keystream для параметров
	var ks [128]uint8
	gen := newXorShift128(seedBytes)
	for i := 0; i < 128; i += 8 {
		v := gen.Next()
		for j := 0; j < 8 && i+j < 128; j++ {
			ks[i+j] = byte((v >> (j * 8)) & 0xFF)
		}
	}

	mul1 := uint8((ks[1] & 0xFE) | 1)
	mul3 := uint8((ks[6] & 0xFE) | 1)

	params.Mask1 = ks[0]
	params.Mul1 = mul1
	params.Mul1Inv = modInverseTable[mul1]
	params.Add1 = ks[2]
	params.Mask2 = ks[3]
	params.Shift2 = ks[4] & 7
	params.Add2 = ks[5]
	params.Mul3 = mul3
	params.Mul3Inv = modInverseTable[mul3]
	params.Add3 = ks[7]
	params.Mask4 = ks[8]
	params.Shift5 = ks[9] & 7
	params.Add5 = ks[10]

	perm := [8]uint8{0, 1, 2, 3, 4, 5, 6, 7}
	for i := 7; i > 0; i-- {
		j := int(gen.Next() % uint64(i+1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	params.Perm = perm

	sbox := [256]uint8{}
	for i := 0; i < 256; i++ {
		sbox[i] = uint8(i)
	}
	for i := 255; i > 0; i-- {
		j := int(gen.Next() % uint64(i+1))
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}
	params.SBox = sbox
	for i := 0; i < 256; i++ {
		params.InvSBox[sbox[i]] = uint8(i)
	}

	opPool := []string{"xrot", "f1", "f2", "f3", "f4", "f5", "swap_nibbles", "reverse_bits", "shuffle_bits"}
	length := int(ks[0]%5) + 5
	if length > len(opPool) {
		length = len(opPool)
	}
	rotOffset := int(ks[1] % uint8(len(opPool)))

	if cap(params.Ops) < length {
		params.Ops = make([]string, length)
	} else {
		params.Ops = params.Ops[:length]
	}

	for i := 0; i < length; i++ {
		idx := (rotOffset + i) % len(opPool)
		params.Ops[i] = opPool[idx]
	}

	if cap(params.OpsCodes) < length {
		params.OpsCodes = make([]int, length)
	} else {
		params.OpsCodes = params.OpsCodes[:length]
	}

	for i, op := range params.Ops {
		switch op {
		case "xrot":
			params.OpsCodes[i] = OpXRot
		case "f1":
			params.OpsCodes[i] = OpF1
		case "f2":
			params.OpsCodes[i] = OpF2
		case "f3":
			params.OpsCodes[i] = OpF3
		case "f4":
			params.OpsCodes[i] = OpF4
		case "f5":
			params.OpsCodes[i] = OpF5
		case "swap_nibbles":
			params.OpsCodes[i] = OpSwapNibbles
		case "reverse_bits":
			params.OpsCodes[i] = OpReverseBits
		case "shuffle_bits":
			params.OpsCodes[i] = OpShuffleBits
		}
	}

	return params
}

// V8 OPT: applyOp с keystream генератором
func (o *Vex3Obfuscator) applyOp(v uint8, params *Vex3Params, ks *keystreamGen, i int, opCode int) uint8 {
	switch opCode {
	case OpXRot:
		k := ks.nextByte()
		shift := ks.nextByte() & 7
		return rotl8(v^k, shift)
	case OpF1:
		t := (v ^ params.Mask1) & 0xFF
		t = (t*params.Mul1 + params.Add1) & 0xFF
		t = (t ^ uint8(i&0xFF)) & 0xFF
		return params.SBox[t]
	case OpF2:
		t := (v + uint8((i*13)&0xFF)) & 0xFF
		t = t ^ params.Mask2
		return rotl8(t, params.Shift2)
	case OpF3:
		return ((v * params.Mul3) & 0xFF) ^ ((params.Add3 + uint8(i)) & 0xFF)
	case OpF4:
		return v ^ rotl8(params.Mask4, uint8(i&7))
	case OpF5:
		t := rotl8(v, params.Shift5)
		return (t + params.Add5) & 0xFF
	case OpSwapNibbles:
		return swapNibbles(v)
	case OpReverseBits:
		return reverseBits(v)
	case OpShuffleBits:
		return shuffleBits(v, params.Perm)
	default:
		return v
	}
}

// V8 OPT: applyOpInv с keystream генератором
func (o *Vex3Obfuscator) applyOpInv(v uint8, params *Vex3Params, ks *keystreamGen, i int, opCode int) uint8 {
	switch opCode {
	case OpXRot:
		k := ks.nextByte()
		shift := ks.nextByte() & 7
		return rotr8(v, shift) ^ k
	case OpF1:
		t := params.InvSBox[v]
		t = ((t ^ uint8(i&0xFF)) - params.Add1) & 0xFF
		t = (t * params.Mul1Inv) & 0xFF
		return t ^ params.Mask1
	case OpF2:
		t := rotr8(v, params.Shift2)
		t = t ^ params.Mask2
		return (t - uint8((i*13)&0xFF)) & 0xFF
	case OpF3:
		t := v ^ ((params.Add3 + uint8(i)) & 0xFF)
		return (t * params.Mul3Inv) & 0xFF
	case OpF4:
		return v ^ rotl8(params.Mask4, uint8(i&7))
	case OpF5:
		t := (v - params.Add5) & 0xFF
		return rotr8(t, params.Shift5)
	case OpSwapNibbles:
		return swapNibbles(v)
	case OpReverseBits:
		return reverseBits(v)
	case OpShuffleBits:
		return unshuffleBits(v, params.Perm)
	default:
		return v
	}
}

func rotl8(b uint8, r uint8) uint8 {
	r &= 7
	return (b << r) | (b >> (8 - r))
}

func rotr8(b uint8, r uint8) uint8 {
	r &= 7
	return (b >> r) | (b << (8 - r))
}

func swapNibbles(b uint8) uint8 {
	return ((b << 4) & 0xF0) | ((b >> 4) & 0x0F)
}

func reverseBits(b uint8) uint8 {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func shuffleBits(b uint8, perm [8]uint8) uint8 {
	var res uint8 = 0
	for srcIdx := 0; srcIdx < 8; srcIdx++ {
		bit := (b >> srcIdx) & 1
		res |= (bit << perm[srcIdx])
	}
	return res
}

func unshuffleBits(b uint8, perm [8]uint8) uint8 {
	inv := [8]uint8{}
	for i, p := range perm {
		inv[p] = uint8(i)
	}
	return shuffleBits(b, inv)
}

type XorShift128 struct {
	a uint64
	b uint64
}

func newXorShift128(seed []byte) *XorShift128 {
	var padded [16]byte
	copy(padded[:], seed)
	return &XorShift128{
		a: binary.LittleEndian.Uint64(padded[:8]),
		b: binary.LittleEndian.Uint64(padded[8:16]),
	}
}

func (x *XorShift128) Next() uint64 {
	mask := uint64(0xFFFFFFFFFFFFFFFF)
	x.a ^= (x.a << 23) & mask
	x.a ^= (x.a >> 17) & mask
	x.b ^= (x.b << 26) & mask
	x.b ^= (x.b >> 11) & mask
	v := (x.a + x.b) & mask
	x.a = (x.a ^ v) & mask
	x.b = (rotl64(v, 13) ^ x.b) & mask
	return v
}

func rotl64(x uint64, r uint64) uint64 {
	r &= 63
	return (x << r) | (x >> (64 - r))
}

func initModInverseTable() [256]uint8 {
	table := [256]uint8{}
	for a := 0; a < 256; a++ {
		if a%2 == 1 {
			table[a] = computeModInverse(uint8(a), 256)
		} else {
			table[a] = 1
		}
	}
	return table
}

func computeModInverse(a uint8, m int) uint8 {
	if a == 0 {
		return 1
	}
	a32 := int32(a)
	m32 := int32(m)
	var t, newt int32 = 0, 1
	var r, newr int32 = m32, a32

	for newr != 0 {
		q := r / newr
		t, newt = newt, t-q*newt
		r, newr = newr, r-q*newr
	}
	if r > 1 {
		return 1
	}
	if t < 0 {
		t += m32
	}
	return uint8(t)
}