package shadowio

const FramePacketLengthBufferSize = 3

const (
	FrameTypeData byte = iota
	FrameTypePadding
	FrameTypeEOF
)
