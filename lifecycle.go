package lampshade

import "context"

// LifecycleListener allows lampshade users to listen to lampshade lifecycle events.
type LifecycleListener interface {
	OnSessionInit(context.Context) context.Context

	OnTCPConnReceived()
	OnReadClientInitError(string)
	OnDecodeClientInitError(string)

	OnTCPStart(context.Context)
	OnTCPEstablished(context.Context)

	OnClientInitWritten(context.Context)
	OnClientInitRead(context.Context)

	OnStreamInit(uint16)
	OnStreamWrite(int)
	OnStreamRead(int)
	OnStreamClose()
}

// NoopLifecycleListener allows callers to use a noop listener.
func NoopLifecycleListener() LifecycleListener {
	return &noopLifecycleListener{}
}

type noopLifecycleListener struct{}

func (n *noopLifecycleListener) OnSessionInit(context.Context) context.Context {
	return context.Background()
}
func (n *noopLifecycleListener) OnTCPConnReceived()                  {}
func (n *noopLifecycleListener) OnReadClientInitError(string)        {}
func (n *noopLifecycleListener) OnDecodeClientInitError(string)      {}
func (n *noopLifecycleListener) OnTCPStart(context.Context)          {}
func (n *noopLifecycleListener) OnTCPEstablished(context.Context)    {}
func (n *noopLifecycleListener) OnClientInitWritten(context.Context) {}
func (n *noopLifecycleListener) OnClientInitRead(context.Context)    {}
func (n *noopLifecycleListener) OnStreamInit(uint16)                 {}
func (n *noopLifecycleListener) OnStreamWrite(int)                   {}
func (n *noopLifecycleListener) OnStreamRead(int)                    {}
func (n *noopLifecycleListener) OnStreamClose()                      {}
