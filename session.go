package connmux

import (
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	coalesceThreshold = 1500 // basically this is the practical TCP MTU for anything traversing Ethernet
)

// session encapsulates the multiplexing of streams onto a single "physical"
// net.Conn.
type session struct {
	net.Conn
	windowSize  int
	pool        BufferPool
	out         chan []byte
	streams     map[uint32]*stream
	closed      map[uint32]bool
	connCh      chan net.Conn
	beforeClose func(*session)
	mx          sync.RWMutex
}

// startSession starts a session on the given net.Conn using the given transmit
// windowSize and pool. If connCh is provided, the session will notify of new
// streams as they are opened. If beforeClose is provided, the session will use
// it to notify when it's about to close.
func startSession(conn net.Conn, windowSize int, pool BufferPool, connCh chan net.Conn, beforeClose func(*session)) *session {
	s := &session{
		Conn:        conn,
		windowSize:  windowSize,
		pool:        pool,
		out:         make(chan []byte),
		streams:     make(map[uint32]*stream),
		closed:      make(map[uint32]bool),
		connCh:      connCh,
		beforeClose: beforeClose,
	}
	go s.sendLoop(pool)
	go s.recvLoop()
	return s
}

func (s *session) recvLoop() {
	for {
		b := s.pool.getForFrame()
		// First read id
		id := b[:idLen]
		_, err := io.ReadFull(s, id)
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		isACK := false
		isRST := false
		switch frameType(id) {
		case frameTypeACK:
			isACK = true
		case frameTypeRST:
			// Closing existing connection
			isRST = true
		}
		setFrameType(id, frameTypeData)

		_id := binaryEncoding.Uint32(id)
		if isACK {
			c, open := s.getOrCreateStream(_id)
			if !open {
				// Stream was already closed, ignore
				continue
			}
			c.sb.ack <- true
			continue
		} else if isRST {
			s.mx.Lock()
			c := s.streams[_id]
			delete(s.streams, _id)
			s.closed[_id] = true
			s.mx.Unlock()
			if c != nil {
				// Close, but don't send an RST back the other way since the other end is
				// already closed.
				c.close(false, nil, nil)
			}
			continue
		}

		// Read frame length
		dataLength := b[idLen:frameHeaderLen]
		_, err = io.ReadFull(s, dataLength)
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		_dataLength := int(binaryEncoding.Uint16(dataLength))

		// Read frame
		b = b[:frameHeaderLen+_dataLength]
		_, err = io.ReadFull(s, b[frameHeaderLen:])
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		c, open := s.getOrCreateStream(_id)
		if !open {
			// Stream was already closed, ignore
			continue
		}
		c.rb.submit(b)
	}
}

func (s *session) sendLoop(pool BufferPool) {
	coalesceBuffer := pool.Get()
	defer pool.Put(coalesceBuffer)

	bufferFrame := func(frame []byte) {
		dataLen := len(frame) - idLen
		if dataLen > MaxDataLen {
			panic(fmt.Sprintf("Data length of %d exceeds maximum allowed of %d", dataLen, MaxDataLen))
		}
		id := frame[dataLen:]
		coalesceBuffer = append(coalesceBuffer, id...)
		if frameType(id) != frameTypeData {
			// control message, no data
			return
		}
		length := make([]byte, lenLen)
		binaryEncoding.PutUint16(length, uint16(dataLen))
		coalesceBuffer = append(coalesceBuffer, length...)
		coalesceBuffer = append(coalesceBuffer, frame[:dataLen]...)
		// Put frame back in pool
		s.pool.Put(frame[:maxFrameLen])
	}

	for frame := range s.out {
		// Coalesce pending writes. This helps with performance and blocking
		// resistence by combining packets.
		coalesceBuffer = coalesceBuffer[:0]
		coalesced := 1
		bufferFrame(frame)
	coalesceLoop:
		for len(coalesceBuffer) < coalesceThreshold {
			select {
			case frame = <-s.out:
				// pending frame immediately available, add it
				bufferFrame(frame)
				coalesced++
			default:
				// no more frames immediately available
				break coalesceLoop
			}
		}

		if log.IsTraceEnabled() {
			log.Tracef("Coalesced %d for total of %d", coalesced, len(coalesceBuffer))
		}
		_, err := s.Write(coalesceBuffer)
		if err != nil {
			s.onSessionError(nil, err)
			return
		}
	}
}

func (s *session) onSessionError(readErr error, writeErr error) {
	s.Close()

	if readErr != nil {
		log.Errorf("Error on reading: %v", readErr)
	} else {
		readErr = ErrBrokenPipe
	}
	if writeErr != nil {
		log.Errorf("Error on writing: %v", writeErr)
	} else {
		writeErr = ErrBrokenPipe
	}
	if readErr == io.EOF {
		// Treat EOF as ErrUnexpectedEOF because the underlying connection should
		// never be out of data until and unless the stream has been closed with an
		// RST frame.
		readErr = io.ErrUnexpectedEOF
	}
	s.mx.RLock()
	streams := make([]*stream, 0, len(s.streams))
	for _, c := range s.streams {
		streams = append(streams, c)
	}
	s.mx.RUnlock()
	for _, c := range streams {
		// Note - we never send an RST because the underlying connection is
		// considered no good at this point and we won't bother sending anything.
		c.close(false, readErr, writeErr)
	}
}

func (s *session) getOrCreateStream(id uint32) (*stream, bool) {
	s.mx.Lock()
	c := s.streams[id]
	if c != nil {
		s.mx.Unlock()
		return c, true
	}
	closed := s.closed[id]
	if closed {
		s.mx.Unlock()
		return nil, false
	}

	_id := make([]byte, idLen)
	binaryEncoding.PutUint32(_id, id)
	c = &stream{
		Conn:    s,
		id:      _id,
		session: s,
		pool:    s.pool,
		rb:      newReceiveBuffer(_id, s.out, s.pool, s.windowSize),
		sb:      newSendBuffer(_id, s.out, s.windowSize),
	}
	s.streams[id] = c
	s.mx.Unlock()
	if s.connCh != nil {
		s.connCh <- c
	}
	return c, true
}

func (s *session) Close() error {
	if s.beforeClose != nil {
		s.beforeClose(s)
	}
	return s.Conn.Close()
}

func (s *session) Wrapped() net.Conn {
	return s.Conn
}

// TODO: do we need a way to close a session/physical connection intentionally?
