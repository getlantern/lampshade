package lampshade

import (
	"context"
	"net"
)

// LifecycleListener allows lampshade users to listen to lampshade lifecycle events.
type LifecycleListener interface {
	OnSessionInit(context.Context) context.Context

	OnTCPConnReceived()
	OnReadClientInitError(string)
	OnDecodeClientInitError(string)

	OnTCPStart(context.Context)
	OnTCPConnectionError(error)
	OnTCPEstablished(net.Conn)

	OnClientInitWritten(context.Context)
	OnClientInitRead(context.Context)

	OnSessionError(readErr error, writeErr error)
	OnStreamInit(context.Context, uint16) StreamLifecycleListener
}

// StreamLifecycleListener allows lampshade users to listen to lampshade lifecycle events for a single stream.
type StreamLifecycleListener interface {
	OnStreamWrite(int)
	OnStreamRead(int)
	OnStreamClose()
}

// NoopLifecycleListener allows callers to use a noop listener.
func NoopLifecycleListener() LifecycleListener {
	return &noopLifecycleListener{}
}

// NoopStreamLifecycleListener allows callers to use a noop listener for a single stream.
func NoopStreamLifecycleListener() StreamLifecycleListener {
	return &noopStreamLifecycleListener{}
}

type noopLifecycleListener struct{}

type noopStreamLifecycleListener struct{}

func (n *noopLifecycleListener) OnSessionInit(context.Context) context.Context {
	return context.Background()
}
func (n *noopLifecycleListener) OnTCPConnReceived()                           {}
func (n *noopLifecycleListener) OnReadClientInitError(string)                 {}
func (n *noopLifecycleListener) OnDecodeClientInitError(string)               {}
func (n *noopLifecycleListener) OnTCPStart(context.Context)                   {}
func (n *noopLifecycleListener) OnTCPConnectionError(error)                   {}
func (n *noopLifecycleListener) OnTCPEstablished(net.Conn)                    {}
func (n *noopLifecycleListener) OnClientInitWritten(context.Context)          {}
func (n *noopLifecycleListener) OnClientInitRead(context.Context)             {}
func (n *noopLifecycleListener) OnSessionError(readErr error, writeErr error) {}
func (n *noopLifecycleListener) OnStreamInit(context.Context, uint16) StreamLifecycleListener {
	return NoopStreamLifecycleListener()
}

func (n *noopStreamLifecycleListener) OnStreamWrite(int) {}
func (n *noopStreamLifecycleListener) OnStreamRead(int)  {}
func (n *noopStreamLifecycleListener) OnStreamClose()    {}
