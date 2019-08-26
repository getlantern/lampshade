package lampshade

import (
	"context"
	"net"
)

// LifecycleListener allows lampshade users to listen to lampshade lifecycle events.
type LifecycleListener interface {
	OnSessionInit(context.Context) context.Context
	OnSessionError(readErr error, writeErr error)
	OnStreamInit(context.Context, uint16) StreamLifecycleListener
}

// ServerLifecycleListener allows lampshade clients to listen to lampshade lifecycle events.
type ServerLifecycleListener interface {
	LifecycleListener

	OnTCPConnReceived(net.Conn)
	OnReadClientInitError(string)
	OnDecodeClientInitError(string)
	OnClientInitRead(context.Context)
}

// ClientLifecycleListener allows lampshade servers to listen to lampshade lifecycle events.
type ClientLifecycleListener interface {
	LifecycleListener

	OnRedialSessionInterval(context.Context)
	OnTCPStart(context.Context)
	OnTCPConnectionError(error)
	OnTCPEstablished(net.Conn)

	OnClientInitWritten(context.Context)
}

// StreamLifecycleListener allows lampshade users to listen to lampshade lifecycle events for a single stream.
type StreamLifecycleListener interface {
	OnStreamWrite(int)
	OnStreamRead(int)
	OnStreamClose()
}

// NoopServerLifecycleListener allows callers to use a noop listener.
func NoopServerLifecycleListener() ServerLifecycleListener {
	return &noopServerLifecycleListener{}
}

// NoopClientLifecycleListener allows callers to use a noop listener.
func NoopClientLifecycleListener() ClientLifecycleListener {
	return &noopClientLifecycleListener{}
}

// NoopStreamLifecycleListener allows callers to use a noop listener for a single stream.
func NoopStreamLifecycleListener() StreamLifecycleListener {
	return &noopStreamLifecycleListener{}
}

type noopServerLifecycleListener struct{}

type noopClientLifecycleListener struct{}

type noopStreamLifecycleListener struct{}

func (n *noopServerLifecycleListener) OnSessionInit(context.Context) context.Context {
	return context.Background()
}

func (n *noopServerLifecycleListener) OnTCPConnReceived(net.Conn)                   {}
func (n *noopServerLifecycleListener) OnReadClientInitError(string)                 {}
func (n *noopServerLifecycleListener) OnDecodeClientInitError(string)               {}
func (n *noopServerLifecycleListener) OnClientInitRead(context.Context)             {}
func (n *noopServerLifecycleListener) OnSessionError(readErr error, writeErr error) {}
func (n *noopServerLifecycleListener) OnStreamInit(context.Context, uint16) StreamLifecycleListener {
	return NoopStreamLifecycleListener()
}

func (n *noopClientLifecycleListener) OnSessionInit(context.Context) context.Context {
	return context.Background()
}
func (n *noopClientLifecycleListener) OnRedialSessionInterval(context.Context)      {}
func (n *noopClientLifecycleListener) OnTCPStart(context.Context)                   {}
func (n *noopClientLifecycleListener) OnTCPConnectionError(error)                   {}
func (n *noopClientLifecycleListener) OnTCPEstablished(net.Conn)                    {}
func (n *noopClientLifecycleListener) OnClientInitWritten(context.Context)          {}
func (n *noopClientLifecycleListener) OnSessionError(readErr error, writeErr error) {}
func (n *noopClientLifecycleListener) OnStreamInit(context.Context, uint16) StreamLifecycleListener {
	return NoopStreamLifecycleListener()
}

func (n *noopStreamLifecycleListener) OnStreamWrite(int) {}
func (n *noopStreamLifecycleListener) OnStreamRead(int)  {}
func (n *noopStreamLifecycleListener) OnStreamClose()    {}
