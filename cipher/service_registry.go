package cipher

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
)

var serviceRegistry map[string]ServiceCreator

func RegisterService(services []string, creator ServiceCreator) {
	if serviceRegistry == nil {
		serviceRegistry = make(map[string]ServiceCreator)
	}
	for _, service := range services {
		serviceRegistry[service] = creator
	}
}

func CreateService(ctx context.Context, serviceName string, options ServiceOptions) (Service, error) {
	if serviceRegistry == nil {
		serviceRegistry = make(map[string]ServiceCreator)
	}
	creator, ok := serviceRegistry[serviceName]
	if !ok {
		return nil, E.New("unknown service: ", serviceName)
	}
	return creator(ctx, serviceName, options)
}
