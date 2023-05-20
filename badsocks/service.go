package badsocks

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"os"
	"time"

	C "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing-shadowsocks2/internal/shadowio"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/replay"
	"github.com/sagernet/sing/common/rw"
)

func init() {
	// C.RegisterService([]string{MethodName}, NewService)
}

type Service struct {
	method       *Method
	handler      C.ServiceHandler
	replayFilter replay.Filter
}

func NewService(ctx context.Context, name string, options C.ServiceOptions) (C.Service, error) {
	method, err := NewMethod(ctx, name, C.MethodOptions{
		Password: options.Password,
		Key:      options.Key,
	})
	if err != nil {
		return nil, err
	}
	if options.Handler == nil {
		return nil, os.ErrInvalid
	}
	return &Service{
		method.(*Method),
		options.Handler,
		replay.NewSimple(60 * time.Second),
	}, nil
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	header := make([]byte, KeySaltLength+shadowio.Overhead+RequestHeaderFixedChunkLength)

	n, err := conn.Read(header)
	if err != nil {
		return E.Cause(err, "read header")
	} else if n < len(header) {
		return ErrBadHeader
	}

	requestSalt := header[:KeySaltLength]

	if !s.replayFilter.Check(requestSalt) {
		return ErrSaltNotUnique
	}

	requestKey := SessionKey(s.method.psk, requestSalt, KeySaltLength)
	readCipher, err := s.method.constructor(common.Dup(requestKey))
	if err != nil {
		return err
	}
	reader := shadowio.NewFrameReader(
		conn,
		readCipher,
	)
	common.KeepAlive(requestKey)

	fixedHeader := buf.New()
	err = reader.Decrypt(fixedHeader.Extend(RequestHeaderFixedChunkLength), header[KeySaltLength:])
	if err != nil {
		return err
	}

	headerType, err := fixedHeader.ReadByte()
	if err != nil {
		return E.Cause(err, "read header")
	}

	if headerType != HeaderTypeClient {
		return E.Extend(ErrBadHeaderType, "expected ", HeaderTypeClient, ", got ", headerType)
	}

	var epoch uint64
	err = binary.Read(fixedHeader, binary.BigEndian, &epoch)
	if err != nil {
		return err
	}

	diff := int(math.Abs(float64(s.method.time().Unix() - int64(epoch))))
	if diff > 30 {
		return E.Extend(ErrBadTimestamp, "received ", epoch, ", diff ", diff, "s")
	}

	var length uint16
	err = binary.Read(fixedHeader, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	_, err = reader.ReadFixedBuffer(int(length))
	if err != nil {
		return err
	}

	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}

	var paddingLen uint16
	err = binary.Read(reader, binary.BigEndian, &paddingLen)
	if err != nil {
		return err
	}

	if reader.CacheLen() < int(paddingLen) {
		return ErrBadPadding
	} else if paddingLen > 0 {
		common.Must(reader.DiscardCache(int(paddingLen)))
	}

	protocolConn := &serverConn{
		method:      s.method,
		Conn:        conn,
		psk:         s.method.psk,
		headerType:  headerType,
		requestSalt: requestSalt,
	}

	protocolConn.reader = reader

	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	return s.handler.NewConnection(ctx, protocolConn, metadata)
}

type serverConn struct {
	net.Conn
	method      *Method
	psk         []byte
	headerType  byte
	reader      *shadowio.FrameReader
	writer      *shadowio.FrameWriter
	requestSalt []byte
	shadowio.FrameWriterInterface
}

func (c *serverConn) writeResponse(payload []byte) error {
	responseSalt := make([]byte, KeySaltLength)
	responseBuffer := buf.New()
	defer responseBuffer.Release()
	responseBuffer.WriteRandom(KeySaltLength)
	copy(responseSalt, responseBuffer.Bytes())
	key := SessionKey(c.method.psk, responseSalt, KeySaltLength)
	writeCipher, err := c.method.constructor(key)
	if err != nil {
		return err
	}
	writer := shadowio.NewFrameWriter(
		c.Conn,
		writeCipher,
		nil,
		buf.BufferSize-shadowio.FramePacketLengthBufferSize-shadowio.Overhead*2,
	)
	fixedLengthHeader := buf.With(responseBuffer.Extend(1 + 8 + KeySaltLength + 2 + shadowio.Overhead))
	common.Must(fixedLengthHeader.WriteByte(HeaderTypeServer))
	common.Must(binary.Write(fixedLengthHeader, binary.BigEndian, uint64(c.method.time().Unix())))
	common.Must1(fixedLengthHeader.Write(c.requestSalt))

	payloadLen := len(payload)
	maxPayloadLen := responseBuffer.FreeLen() - shadowio.Overhead
	if payloadLen > maxPayloadLen {
		payloadLen = maxPayloadLen
	}

	common.Must(binary.Write(fixedLengthHeader, binary.BigEndian, uint16(payloadLen)))
	writer.Encrypt(fixedLengthHeader.Index(0), fixedLengthHeader.Bytes())
	c.requestSalt = nil
	if payloadLen > 0 {
		payloadBuffer := buf.With(responseBuffer.Extend(payloadLen + shadowio.Overhead))
		common.Must1(payloadBuffer.Write(payload[:payloadLen]))
		writer.Encrypt(payloadBuffer.Index(0), payloadBuffer.Bytes())
	}

	_, err = c.Conn.Write(responseBuffer.Bytes())
	if err != nil {
		return err
	}

	if len(payload) > payloadLen {
		_, err = writer.Write(payload[payloadLen:])
		if err != nil {
			return err
		}
	}
	c.writer = writer
	return nil
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) ReadBufferThreadSafe() (buffer *buf.Buffer, err error) {
	return c.reader.ReadBufferThreadSafe()
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse(p)
		if err == nil {
			n = len(p)
		}
		return
	}
	return c.writer.Write(p)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		defer buffer.Release()
		return c.writeResponse(buffer.Bytes())
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *serverConn) NeedHandshake() bool {
	return c.writer == nil
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.Conn
}

func (c *serverConn) CloseWrite() error {
	c.writer.CloseWrite()
	return rw.CloseWrite(c.Conn)
}

func (c *serverConn) Close() error {
	return common.Close(
		c.Conn,
		common.PtrOrNil(c.reader),
		common.PtrOrNil(c.writer),
	)
}
