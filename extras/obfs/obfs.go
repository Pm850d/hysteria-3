package obfs

import (
	"errors"
	"strings"
)

type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

func NewObfuscator(t string, password []byte) (Obfuscator, error) {
	switch strings.ToLower(t) {
	case "salamander":
		return NewSalamanderObfuscator(password)
	case "vex3":
		return NewVex3Obfuscator(password)
	default:
		return nil, errors.New("unsupported obfuscation type: " + t)
	}
}