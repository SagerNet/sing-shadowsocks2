package shadowio

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type FrameReader struct {
	reader io.Reader
	cipher cipher.AEAD
	nonce  []byte
	cache  *buf.Buffer
}

func NewFrameReader(upstream io.Reader, cipher cipher.AEAD) *FrameReader {
	return &FrameReader{
		reader: upstream,
		cipher: cipher,
		nonce:  make([]byte, cipher.NonceSize()),
	}
}

func (r *FrameReader) CacheLen() int {
	cache := r.cache
	if cache == nil {
		return 0
	}
	return cache.Len()
}

func (r *FrameReader) DiscardCache(pLen int) error {
	if r.cache == nil || r.cache.Len() < pLen {
		return io.ErrUnexpectedEOF
	}
	r.cache.Advance(pLen)
	if r.cache.IsEmpty() {
		r.cache.Release()
		r.cache = nil
	}
	return nil
}

func (r *FrameReader) ReadFixedBuffer(pLen int) (*buf.Buffer, error) {
	buffer := buf.NewSize(pLen + Overhead)
	_, err := buffer.ReadFullFrom(r.reader, buffer.FreeLen())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	err = r.Decrypt(buffer.Index(0), buffer.Bytes())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Truncate(pLen)
	r.cache = buffer
	return buffer, nil
}

func (r *FrameReader) Decrypt(destination []byte, source []byte) error {
	_, err := r.cipher.Open(destination[:0], r.nonce, source, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	return nil
}

func (r *FrameReader) Read(p []byte) (n int, err error) {
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n = copy(p, r.cache.Bytes())
				if n > 0 {
					r.cache.Advance(n)
					return
				}
			}
		}
		r.cache, err = r.readBuffer()
		if err != nil {
			return
		}
	}
}

func (r *FrameReader) ReadBuffer(buffer *buf.Buffer) error {
	var err error
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n := copy(buffer.FreeBytes(), r.cache.Bytes())
				if n > 0 {
					r.cache.Advance(n)
					return nil
				}
			}
		}
		r.cache, err = r.readBuffer()
		if err != nil {
			return err
		}
	}
}

func (r *FrameReader) ReadBufferThreadSafe() (buffer *buf.Buffer, err error) {
	cache := r.cache
	if cache != nil {
		r.cache = nil
		return cache, nil
	}
	return r.readBuffer()
}

func (r *FrameReader) readBuffer() (*buf.Buffer, error) {
	buffer := buf.NewSize(FramePacketLengthBufferSize + Overhead)
	_, err := buffer.ReadFullFrom(r.reader, buffer.FreeLen())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	_, err = r.cipher.Open(buffer.Index(0), r.nonce, buffer.Bytes(), nil)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	increaseNonce(r.nonce)
	frameType := buffer.Byte(0)
	length := int(binary.BigEndian.Uint16(buffer.Range(1, FramePacketLengthBufferSize)))
	buffer.Release()
	if length > 0 {
		if frameType == FrameTypeData {
			buffer = buf.NewSize(length + Overhead)
		} else {
			buffer = buf.NewSize(length)
		}
		_, err = buffer.ReadFullFrom(r.reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
	}
	switch frameType {
	case FrameTypeData:
		_, err = r.cipher.Open(buffer.Index(0), r.nonce, buffer.Bytes(), nil)
		if err != nil {
			buffer.Release()
			return nil, err
		}
		increaseNonce(r.nonce)
		buffer.Truncate(length)
		return buffer, nil
	case FrameTypePadding:
		return r.readBuffer()
	case FrameTypeEOF:
		return nil, io.EOF
	default:
		return nil, E.New("unknown frame type: ", frameType)
	}
}
