package shadowio

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	MaxPaddingLength = 900
	FirstPaddings    = 16
)

type FrameWriter struct {
	FrameWriterInterface
	writer           N.ExtendedWriter
	cipher           cipher.AEAD
	maxPacketSize    int
	nonce            []byte
	access           sync.Mutex
	closed           bool
	writePadding     int
	paddingRemaining atomic.Int32
	done             chan struct{}
}

func NewFrameWriter(writer io.Writer, cipher cipher.AEAD, nonce []byte, maxPacketSize int) *FrameWriter {
	if len(nonce) == 0 {
		nonce = make([]byte, cipher.NonceSize())
	}
	return &FrameWriter{
		writer:        bufio.NewExtendedWriter(writer),
		cipher:        cipher,
		nonce:         nonce,
		maxPacketSize: maxPacketSize,
		writePadding:  FirstPaddings,
		done:          make(chan struct{}),
	}
}

func (w *FrameWriter) Encrypt(destination []byte, source []byte) {
	w.cipher.Seal(destination, w.nonce, source, nil)
	increaseNonce(w.nonce)
}

func (w *FrameWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	w.access.Lock()
	defer w.access.Unlock()
	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > w.maxPacketSize {
			data = p[:w.maxPacketSize]
			p = p[w.maxPacketSize:]
			pLen -= w.maxPacketSize
		} else {
			data = p
			pLen = 0
		}
		bufferSize := FramePacketLengthBufferSize + 2*Overhead + len(data)
		var paddingLen int
		switch {
		case w.writePadding > 0:
			w.writePadding--
			fallthrough
		case pLen < MaxPaddingLength && rand.Intn(3) == 2:
			paddingLen = 1 + rand.Intn(MaxPaddingLength)
			bufferSize += FramePacketLengthBufferSize + Overhead + paddingLen
		}
		buffer := buf.NewSize(bufferSize)
		common.Must(buffer.WriteByte(FrameTypeData))
		common.Must(binary.Write(buffer, binary.BigEndian, uint16(len(data))))
		w.cipher.Seal(buffer.Index(0), w.nonce, buffer.To(FramePacketLengthBufferSize), nil)
		increaseNonce(w.nonce)
		buffer.Extend(Overhead)
		w.cipher.Seal(buffer.Index(buffer.Len()), w.nonce, data, nil)
		buffer.Extend(len(data) + Overhead)
		increaseNonce(w.nonce)
		if paddingLen > 0 {
			padding := buf.With(buffer.Extend(FramePacketLengthBufferSize + Overhead + paddingLen))
			common.Must(padding.WriteByte(FrameTypePadding))
			common.Must(binary.Write(padding, binary.BigEndian, uint16(paddingLen)))
			w.cipher.Seal(padding.Index(0), w.nonce, padding.Bytes(), nil)
			increaseNonce(w.nonce)
			padding.Extend(Overhead)
			padding.WriteRandom(padding.FreeLen())
			w.schedulePadding()
		}
		_, err = w.writer.Write(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return
		}
		n += len(data)
	}
	return
}

func (w *FrameWriter) WritePadding(pLen int) error {
	w.access.Lock()
	defer w.access.Unlock()
	bufferSize := FramePacketLengthBufferSize + Overhead + pLen
	buffer := buf.NewSize(bufferSize)
	defer buffer.Release()
	common.Must(buffer.WriteByte(FrameTypePadding))
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(pLen)))
	w.cipher.Seal(buffer.Index(0), w.nonce, buffer.Bytes(), nil)
	increaseNonce(w.nonce)
	buffer.Extend(Overhead)
	buffer.WriteRandom(buffer.FreeLen())
	return common.Error(w.writer.Write(buffer.Bytes()))
}

func (w *FrameWriter) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.Len() > w.maxPacketSize {
		defer buffer.Release()
		return common.Error(w.Write(buffer.Bytes()))
	}
	pLen := buffer.Len()
	headerOffset := FramePacketLengthBufferSize + Overhead
	header := buf.With(buffer.ExtendHeader(headerOffset))
	common.Must(header.WriteByte(FrameTypeData))
	common.Must(binary.Write(header, binary.BigEndian, uint16(pLen)))
	w.access.Lock()
	defer w.access.Unlock()
	w.cipher.Seal(header.Index(0), w.nonce, header.Bytes(), nil)
	increaseNonce(w.nonce)
	w.cipher.Seal(buffer.Index(headerOffset), w.nonce, buffer.From(headerOffset), nil)
	increaseNonce(w.nonce)
	buffer.Extend(Overhead)
	switch {
	case w.writePadding > 0:
		w.writePadding--
		fallthrough
	case pLen < MaxPaddingLength && rand.Intn(3) == 2:
		paddingLen := 1 + rand.Intn(MaxPaddingLength)
		padding := buf.With(buffer.Extend(FramePacketLengthBufferSize + Overhead + paddingLen))
		common.Must(padding.WriteByte(FrameTypePadding))
		common.Must(binary.Write(padding, binary.BigEndian, uint16(paddingLen)))
		w.cipher.Seal(padding.Index(0), w.nonce, padding.Bytes(), nil)
		increaseNonce(w.nonce)
		padding.Extend(Overhead)
		padding.WriteRandom(padding.FreeLen())
		w.schedulePadding()
	}
	return w.writer.WriteBuffer(buffer)
}

func (w *FrameWriter) schedulePadding() {
	if w.paddingRemaining.Load() >= 3 {
		return
	}
	w.paddingRemaining.Add(1)
	go func() {
		defer w.paddingRemaining.Add(-1)
		select {
		case <-time.After(time.Duration(rand.Intn(1024)) * time.Millisecond):
		case <-w.done:
			return
		}
		_ = w.WritePadding(1 + rand.Intn(MaxPaddingLength))
	}()
}

func (w *FrameWriter) CloseWrite() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

func (w *FrameWriter) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	return nil
}

func (w *FrameWriter) TakeNonce() []byte {
	return w.nonce
}

func (w *FrameWriter) Upstream() any {
	return w.writer
}

type FrameWriterInterface struct{}

func (w *FrameWriterInterface) FrontHeadroom() int {
	return FramePacketLengthBufferSize + Overhead
}

func (w *FrameWriterInterface) RearHeadroom() int {
	return Overhead*2 + FramePacketLengthBufferSize + MaxPaddingLength
}
