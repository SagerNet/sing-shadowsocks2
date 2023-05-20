package badsocks

import (
	"crypto/cipher"
	"crypto/sha256"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/random"

	"lukechampine.com/blake3"
)

const (
	KeySaltLength = 16
)

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	RequestHeaderFixedChunkLength = 1 + 8 + 2
	PacketMinimalHeaderSize       = 30
)

var (
	ErrBadHeaderType  = E.New("bad header type")
	ErrBadTimestamp   = E.New("bad timestamp")
	ErrBadRequestSalt = E.New("bad request salt")
	ErrSaltNotUnique  = E.New("salt not unique")
	ErrBadHeader      = E.New("bad header")
	ErrBadPadding     = E.New("bad request: damaged padding")
)

func init() {
	random.InitializeSeed()
}

func Key(key []byte) []byte {
	psk := sha256.Sum256(key)
	return psk[:KeySaltLength]
}

func SessionKey(psk []byte, salt []byte, keyLength int) []byte {
	sessionKey := buf.Make(len(psk) + len(salt))
	copy(sessionKey, psk)
	copy(sessionKey[len(psk):], salt)
	outKey := buf.Make(keyLength)
	blake3.DeriveKey(outKey, "badsocks session subkey", sessionKey)
	return outKey
}

func aeadCipher(block func(key []byte) (cipher.Block, error), aead func(block cipher.Block) (cipher.AEAD, error)) func(key []byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		b, err := block(key)
		if err != nil {
			return nil, err
		}
		return aead(b)
	}
}
