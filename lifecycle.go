package lampshade

import (
	"context"
	"net"
)

// LifecycleListener allows lampshade users to listen to lampshade lifecycle events.
type LifecycleListener interface {
	OnSessionInit(context.Context) context.Context
	OnSessionError(context.Context, error, error) context.Context
	OnStreamInit(context.Context, uint16) StreamLifecycleListener
	OnTCPClosed(context.Context) context.Context
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

	OnTCPStart(context.Context) context.Context
	OnTCPConnectionError(context.Context, error) context.Context
	OnTCPEstablished(context.Context, net.Conn) context.Context
	OnClientInitWritten(context.Context) context.Context
}

// StreamLifecycleListener allows lampshade users to listen to lampshade lifecycle events for a single stream.
type StreamLifecycleListener interface {
	OnStreamWrite(int)
	OnStreamRead(int)
	OnStreamClose()
}

// NoopServerLifecycleListener allows callers to use a noop listener.
func NoopServerLifecycleListener() ServerLifecycleListener {
	return &noopServerLifecycleListener{&noopLifecycleListener{}}
}

// NoopClientLifecycleListener allows callers to use a noop listener.
func NoopClientLifecycleListener() ClientLifecycleListener {
	return &noopClientLifecycleListener{&noopLifecycleListener{}}
}

// NoopStreamLifecycleListener allows callers to use a noop listener for a single stream.
func NoopStreamLifecycleListener() StreamLifecycleListener {
	return &noopStreamLifecycleListener{}
}

type noopLifecycleListener struct{}

type noopServerLifecycleListener struct {
	LifecycleListener
}

type noopClientLifecycleListener struct {
	LifecycleListener
}

type noopStreamLifecycleListener struct{}

func (n *noopLifecycleListener) OnSessionInit(context.Context) context.Context {
	return context.Background()
}
func (n *noopLifecycleListener) OnStreamInit(context.Context, uint16) StreamLifecycleListener {
	return NoopStreamLifecycleListener()
}
func (n *noopLifecycleListener) OnSessionError(ctx context.Context, err1 error, err2 error) context.Context {
	return ctx
}
func (n *noopLifecycleListener) OnTCPClosed(ctx context.Context) context.Context { return ctx }

func (n *noopServerLifecycleListener) OnTCPConnReceived(net.Conn)       {}
func (n *noopServerLifecycleListener) OnReadClientInitError(string)     {}
func (n *noopServerLifecycleListener) OnDecodeClientInitError(string)   {}
func (n *noopServerLifecycleListener) OnClientInitRead(context.Context) {}

func (n *noopClientLifecycleListener) OnTCPStart(ctx context.Context) context.Context { return ctx }
func (n *noopClientLifecycleListener) OnTCPConnectionError(ctx context.Context, err error) context.Context {
	return ctx
}
func (n *noopClientLifecycleListener) OnTCPEstablished(ctx context.Context, conn net.Conn) context.Context {
	return ctx
}
func (n *noopClientLifecycleListener) OnClientInitWritten(ctx context.Context) context.Context {
	return ctx
}

func (n *noopStreamLifecycleListener) OnStreamWrite(int) {}
func (n *noopStreamLifecycleListener) OnStreamRead(int)  {}
func (n *noopStreamLifecycleListener) OnStreamClose()    {}
