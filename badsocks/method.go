package badsocks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"math"
	mRand "math/rand"
	"net"
	"time"

	C "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing-shadowsocks2/internal/shadowio"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/rw"
)

var MethodName = "badsocks"

func init() {
	// C.RegisterMethod([]string{MethodName}, NewMethod)
}

type Method struct {
	timeFunc    func() time.Time
	constructor func(key []byte) (cipher.AEAD, error)
	psk         []byte
}

func NewMethod(ctx context.Context, methodName string, options C.MethodOptions) (C.Method, error) {
	m := &Method{
		timeFunc:    ntp.TimeFuncFromContext(ctx),
		constructor: aeadCipher(aes.NewCipher, cipher.NewGCM),
	}
	if kLen := len(options.Key); kLen != 0 {
		if kLen != KeySaltLength {
			return nil, E.New("bad key length")
		}
		m.psk = options.Key
	} else if options.Password != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(options.Password)
		if err == nil && len(keyBytes) == KeySaltLength {
			m.psk = keyBytes
		} else {
			m.psk = Key([]byte(options.Password))
		}
	} else {
		return nil, C.ErrMissingPassword
	}
	return m, nil
}

func (m *Method) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	shadowsocksConn := &clientConn{
		Conn:        conn,
		method:      m,
		destination: destination,
	}
	return shadowsocksConn, shadowsocksConn.writeRequest(nil)
}

func (m *Method) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return &clientConn{
		Conn:        conn,
		method:      m,
		destination: destination,
	}
}

func (m *Method) DialPacketConn(conn net.Conn) N.NetPacketConn {
	return nil
}

func (m *Method) time() time.Time {
	if m.timeFunc != nil {
		return m.timeFunc()
	} else {
		return time.Now()
	}
}

type clientConn struct {
	net.Conn
	method      *Method
	destination M.Socksaddr
	requestSalt []byte
	reader      *shadowio.FrameReader
	writer      *shadowio.FrameWriter
	shadowio.FrameWriterInterface
}

func (c *clientConn) writeRequest(payload []byte) error {
	requestSalt := make([]byte, KeySaltLength)
	requestBuffer := buf.New()
	defer requestBuffer.Release()
	requestBuffer.WriteRandom(KeySaltLength)
	copy(requestSalt, requestBuffer.Bytes())
	key := SessionKey(c.method.psk, requestSalt, KeySaltLength)
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
	fixedLengthBuffer := buf.With(requestBuffer.Extend(RequestHeaderFixedChunkLength + shadowio.Overhead))
	common.Must(fixedLengthBuffer.WriteByte(HeaderTypeClient))
	common.Must(binary.Write(fixedLengthBuffer, binary.BigEndian, uint64(c.method.time().Unix())))
	variableLengthHeaderLen := M.SocksaddrSerializer.AddrPortLen(c.destination) + 2
	var paddingLen int
	if len(payload) < MaxPaddingLength {
		paddingLen = mRand.Intn(MaxPaddingLength) + 1
	}
	variableLengthHeaderLen += paddingLen
	maxPayloadLen := requestBuffer.FreeLen() - (variableLengthHeaderLen + shadowio.Overhead)
	payloadLen := len(payload)
	if payloadLen > maxPayloadLen {
		payloadLen = maxPayloadLen
	}
	variableLengthHeaderLen += payloadLen
	common.Must(binary.Write(fixedLengthBuffer, binary.BigEndian, uint16(variableLengthHeaderLen)))
	writer.Encrypt(fixedLengthBuffer.Index(0), fixedLengthBuffer.Bytes())
	fixedLengthBuffer.Extend(shadowio.Overhead)

	variableLengthBuffer := buf.With(requestBuffer.Extend(variableLengthHeaderLen + shadowio.Overhead))
	common.Must(M.SocksaddrSerializer.WriteAddrPort(variableLengthBuffer, c.destination))
	common.Must(binary.Write(variableLengthBuffer, binary.BigEndian, uint16(paddingLen)))
	if paddingLen > 0 {
		variableLengthBuffer.Extend(paddingLen)
	}
	if payloadLen > 0 {
		common.Must1(variableLengthBuffer.Write(payload[:payloadLen]))
	}
	writer.Encrypt(variableLengthBuffer.Index(0), variableLengthBuffer.Bytes())
	variableLengthBuffer.Extend(shadowio.Overhead)
	_, err = c.Conn.Write(requestBuffer.Bytes())
	if err != nil {
		return err
	}
	if len(payload) > payloadLen {
		_, err = writer.Write(payload[payloadLen:])
		if err != nil {
			return err
		}
	}
	c.requestSalt = requestSalt
	c.writer = writer
	return nil
}

func (c *clientConn) readResponse() error {
	salt := buf.NewSize(KeySaltLength)
	defer salt.Release()
	_, err := salt.ReadFullFrom(c.Conn, KeySaltLength)
	if err != nil {
		return err
	}
	readCipher, err := c.method.constructor(SessionKey(c.method.psk, salt.Bytes(), KeySaltLength))
	if err != nil {
		return err
	}
	reader := shadowio.NewFrameReader(c.Conn, readCipher)
	fixedResponseBuffer, err := reader.ReadFixedBuffer(1 + 8 + KeySaltLength + 2)
	if err != nil {
		return err
	}
	headerType := common.Must1(fixedResponseBuffer.ReadByte())
	if headerType != HeaderTypeServer {
		return E.Extend(ErrBadHeaderType, "expected ", HeaderTypeServer, ", got ", headerType)
	}
	var epoch uint64
	common.Must(binary.Read(fixedResponseBuffer, binary.BigEndian, &epoch))
	diff := int(math.Abs(float64(c.method.time().Unix() - int64(epoch))))
	if diff > 30 {
		return E.Extend(ErrBadTimestamp, "received ", epoch, ", diff ", diff, "s")
	}
	responseSalt := common.Must1(fixedResponseBuffer.ReadBytes(KeySaltLength))
	if !bytes.Equal(responseSalt, c.requestSalt) {
		return ErrBadRequestSalt
	}
	var length uint16
	common.Must(binary.Read(reader, binary.BigEndian, &length))
	_, err = reader.ReadFixedBuffer(int(length))
	if err != nil {
		return err
	}
	c.reader = reader
	return nil
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.reader == nil {
		if err = c.readResponse(); err != nil {
			return
		}
	}
	return c.reader.Read(p)
}

func (c *clientConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.reader == nil {
		err := c.readResponse()
		if err != nil {
			return err
		}
	}
	return c.reader.ReadBuffer(buffer)
}

func (c *clientConn) ReadBufferThreadSafe() (buffer *buf.Buffer, err error) {
	if c.reader == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	return c.reader.ReadBufferThreadSafe()
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeRequest(p)
		if err == nil {
			n = len(p)
		}
		return
	}
	return c.writer.Write(p)
}

func (c *clientConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		defer buffer.Release()
		return c.writeRequest(buffer.Bytes())
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *clientConn) NeedHandshake() bool {
	return c.writer == nil
}

func (c *clientConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *clientConn) Upstream() any {
	return c.Conn
}

func (c *clientConn) CloseWrite() error {
	c.writer.CloseWrite()
	return rw.CloseWrite(c.Conn)
}

func (c *clientConn) Close() error {
	return common.Close(
		c.Conn,
		common.PtrOrNil(c.reader),
		common.PtrOrNil(c.writer),
	)
}
