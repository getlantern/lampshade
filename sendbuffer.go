package connmux

import (
	"time"
)

var (
	closeTimeout = 30 * time.Second
)

// sendBuffer buffers outgoing frames. It holds up to <windowSize> frames,
// after which it starts back-pressuring.
//
// It sends an initial <windowSize> frames. After that, in order to avoid
// filling the receiver's receiveBuffer, it waits for ACKs from the receiver
// before sending new frames.
//
// When closed normally it sends an RST frame to the receiver to indicate that
// the connection is closed. We handle this from sendBuffer so that we can
// ensure buffered frames are sent before sending the RST.
type sendBuffer struct {
	streamID       []byte
	in             chan []byte
	ack            chan bool
	closeRequested chan bool
}

func newSendBuffer(streamID []byte, out chan []byte, windowSize int) *sendBuffer {
	buf := &sendBuffer{
		streamID:       streamID,
		in:             make(chan []byte, windowSize),
		ack:            make(chan bool, windowSize),
		closeRequested: make(chan bool, 1),
	}
	// Write initial acks to send up to windowSize right away
	for i := 0; i < windowSize; i++ {
		buf.ack <- true
	}
	go buf.sendLoop(out)
	return buf
}

func (buf *sendBuffer) sendLoop(out chan []byte) {
	sendRST := false

	defer func() {
		if sendRST {
			buf.sendRST(out)
		}

		// drain remaining writes
		for range buf.in {
		}
	}()

	closeTimer := time.NewTimer(largeTimeout)
	signalClose := func() {
		close(buf.in)
		closeTimer.Reset(closeTimeout)
	}

	// Send one frame for every ack
	for {
		select {
		case <-buf.ack:
			// Grab next frame
			select {
			case frame, open := <-buf.in:
				if frame != nil {
					out <- append(frame, buf.streamID...)
				}
				if !open {
					// We've closed
					return
				}
			case sendRST = <-buf.closeRequested:
				signalClose()
			}
		case sendRST = <-buf.closeRequested:
			// Signal that we're closing
			signalClose()
		case <-closeTimer.C:
			// We had queued writes, but we haven't gotten any acks within
			// closeTimeout of closing, don't wait any longer
			return
		}
	}
}

func (buf *sendBuffer) close(sendRST bool) {
	select {
	case buf.closeRequested <- sendRST:
		// okay
	default:
		// close already requested, ignore
	}
}

func (buf *sendBuffer) sendRST(out chan []byte) {
	// Send an RST frame with the streamID
	rst := make([]byte, len(buf.streamID))
	copy(rst, buf.streamID)
	setFrameType(rst, frameTypeRST)
	out <- rst
}
