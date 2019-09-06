package lampshade

import (
	"context"
	"net"
)

// LifecycleListener allows lampshade users to listen to lampshade lifecycle events.
type LifecycleListener interface {
	OnTCPStart() SessionLifecycleListener
}

// ServerLifecycleListener allows lampshade clients to listen to lampshade lifecycle events.
type ServerLifecycleListener interface {
	LifecycleListener

	OnReadClientInitError(string)
	OnDecodeClientInitError(string)
	OnClientInitRead()
}

// ClientLifecycleListener allows lampshade servers to listen to lampshade lifecycle events.
type ClientLifecycleListener interface {
	LifecycleListener

	OnStart()
}

// SessionLifecycleListener is a listener for events on a single session (TCP connection)
type SessionLifecycleListener interface {
	OnTCPConnectionError(error)
	OnTCPEstablished(net.Conn)
	OnClientInitWritten()
	OnSessionInit()
	OnSessionError(error, error)
	OnTCPClosed()

	OnStreamStart(context.Context, uint16) StreamLifecycleListener
}

// StreamLifecycleListener allows lampshade users to listen to lampshade lifecycle events for a single stream.
type StreamLifecycleListener interface {
	OnStreamWrite(int)
	OnStreamRead(int)
	OnStreamWriteError(error)
	OnStreamReadError(error)
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

// NoopSessionLifecycleListener allows callers to use a noop listener for a single stream.
func NoopSessionLifecycleListener() SessionLifecycleListener {
	return &noopSessionLifecycleListener{}
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

type noopSessionLifecycleListener struct{}

type noopStreamLifecycleListener struct{}

func (n *noopLifecycleListener) OnTCPStart() SessionLifecycleListener {
	return NoopSessionLifecycleListener()
}

func (n *noopServerLifecycleListener) OnReadClientInitError(string)   {}
func (n *noopServerLifecycleListener) OnDecodeClientInitError(string) {}
func (n *noopServerLifecycleListener) OnClientInitRead()              {}

func (n *noopClientLifecycleListener) OnStart() {}

func (n *noopSessionLifecycleListener) OnSessionInit() {}
func (n *noopSessionLifecycleListener) OnStreamStart(context.Context, uint16) StreamLifecycleListener {
	return NoopStreamLifecycleListener()
}
func (n *noopSessionLifecycleListener) OnSessionError(err1 error, err2 error) {}
func (n *noopSessionLifecycleListener) OnTCPClosed()                          {}
func (n *noopSessionLifecycleListener) OnTCPConnectionError(err error)        {}
func (n *noopSessionLifecycleListener) OnTCPEstablished(net.Conn)             {}
func (n *noopSessionLifecycleListener) OnClientInitWritten()                  {}

func (n *noopStreamLifecycleListener) OnStreamWrite(int)        {}
func (n *noopStreamLifecycleListener) OnStreamRead(int)         {}
func (n *noopStreamLifecycleListener) OnStreamWriteError(error) {}
func (n *noopStreamLifecycleListener) OnStreamReadError(error)  {}
func (n *noopStreamLifecycleListener) OnStreamClose()           {}
