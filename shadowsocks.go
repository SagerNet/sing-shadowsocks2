package shadowsocks

import (
	"context"

	_ "github.com/sagernet/sing-shadowsocks2/badsocks"
	C "github.com/sagernet/sing-shadowsocks2/cipher"
	_ "github.com/sagernet/sing-shadowsocks2/shadowaead"
	_ "github.com/sagernet/sing-shadowsocks2/shadowaead_2022"
	_ "github.com/sagernet/sing-shadowsocks2/shadowstream"
)

type (
	Method         = C.Method
	MethodOptions  = C.MethodOptions
	Service        = C.Service
	ServiceHandler = C.ServiceHandler
	ServiceOptions = C.ServiceOptions
)

func CreateMethod(ctx context.Context, method string, options MethodOptions) (Method, error) {
	return C.CreateMethod(ctx, method, options)
}

func CreateService(ctx context.Context, method string, options ServiceOptions) (Service, error) {
	return C.CreateService(ctx, method, options)
}
