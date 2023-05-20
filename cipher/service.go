package cipher

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

type Service interface {
	N.TCPConnectionHandler
}

type ServiceHandler interface {
	N.TCPConnectionHandler
}

type ServiceOptions struct {
	Password string
	Key      []byte
	Handler  ServiceHandler
}

type ServiceCreator func(ctx context.Context, methodName string, options ServiceOptions) (Service, error)
