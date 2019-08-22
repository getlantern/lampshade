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
