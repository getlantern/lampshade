package lampshade

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
)

// session encapsulates the multiplexing of streams onto a single "physical"
// net.Conn.
type session struct {
	net.Conn
	windowSize    int
	maxPadding    *big.Int
	decrypt       func([]byte)                 // decrypt in place
	encrypt       func(dst []byte, src []byte) // encrypt to a destination
	clientInitMsg []byte
	pool          BufferPool
	out           chan []byte
	streams       map[uint16]*stream
	closed        map[uint16]bool
	connCh        chan net.Conn
	beforeClose   func(*session)
	mx            sync.RWMutex
}

// startSession starts a session on the given net.Conn using the given transmit
// windowSize and pool. If connCh is provided, the session will notify of new
// streams as they are opened. If beforeClose is provided, the session will use
// it to notify when it's about to close.
func startSession(conn net.Conn, windowSize int, maxPadding int, decrypt cipher.Stream, encrypt cipher.Stream, clientInitMsg []byte, pool BufferPool, connCh chan net.Conn, beforeClose func(*session)) *session {
	s := &session{
		Conn:          conn,
		windowSize:    windowSize,
		maxPadding:    big.NewInt(int64(maxPadding)),
		decrypt:       func(b []byte) { decrypt.XORKeyStream(b, b) },
		encrypt:       func(dst []byte, src []byte) { encrypt.XORKeyStream(dst, src) },
		clientInitMsg: clientInitMsg,
		pool:          pool,
		out:           make(chan []byte),
		streams:       make(map[uint16]*stream),
		closed:        make(map[uint16]bool),
		connCh:        connCh,
		beforeClose:   beforeClose,
	}
	go s.sendLoop()
	go s.recvLoop()
	return s
}

func (s *session) recvLoop() {
	for {
		b := s.pool.getForFrame()
		// First read header
		header := b[:headerSize]
		_, err := io.ReadFull(s, header)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to read header: %v", err), nil)
			return
		}

		frameType, id := frameTypeAndID(header)
		isPadding := false
		switch frameType {
		case frameTypePadding:
			isPadding = true
		case frameTypeACK:
			c, open := s.getOrCreateStream(id)
			if !open {
				// Stream was already closed, ignore
				continue
			}
			c.sb.ack <- true
			continue
		case frameTypeRST:
			// Closing existing connection
			s.mx.Lock()
			c := s.streams[id]
			delete(s.streams, id)
			s.closed[id] = true
			s.mx.Unlock()
			if c != nil {
				// Close, but don't send an RST back the other way since the other end is
				// already closed.
				c.close(false, nil, nil)
			}
			continue
		}

		// Read frame length
		dataLength := b[headerSize:fullHeaderSize]
		_, err = io.ReadFull(s, dataLength)
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		_dataLength := int(binaryEncoding.Uint16(dataLength))
		// Read frame
		b = b[:fullHeaderSize+_dataLength]
		_, err = io.ReadFull(s, b[fullHeaderSize:])
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		if isPadding {
			// don't do anything with padding after we've read it
			continue
		}

		c, open := s.getOrCreateStream(id)
		if !open {
			// Stream was already closed, ignore
			continue
		}
		c.rb.submit(b)
	}
}

func (s *session) sendLoop() {
	// Use maxFrameSize * 2 for coalesce buffer to avoid having to grow it
	coalesceBuffer := make([]byte, maxFrameSize*2)
	coalescedBytes := 0

	// pre-allocate buffer for length to avoid extra allocations
	lengthBuffer := make([]byte, lenSize)

	// pre-allocate empty buffer for random padding
	// note - we can use an empty buffer because after encryption with AES in CTR
	// mode it is effectively random anyway.
	randomPadding := make([]byte, fullHeaderSize+int(s.maxPadding.Int64()))
	setFrameType(randomPadding, frameTypePadding)

	coalesce := func(b []byte) {
		dst := coalesceBuffer[coalescedBytes:]
		s.encrypt(dst, b)
		coalescedBytes += len(b)
	}

	bufferFrame := func(frame []byte) {
		dataLen := len(frame) - headerSize
		if dataLen > MaxDataLen {
			panic(fmt.Sprintf("Data length of %d exceeds maximum allowed of %d", dataLen, MaxDataLen))
		}
		header := frame[dataLen:]
		coalesce(header)
		if frameType(header) != frameTypeData {
			// control message, no data
			return
		}
		binaryEncoding.PutUint16(lengthBuffer, uint16(dataLen))
		coalesce(lengthBuffer)
		coalesce(frame[:dataLen])
		// Put frame back in pool
		s.pool.Put(frame[:maxFrameSize])
	}

	for frame := range s.out {
		// Coalesce pending writes. This helps with performance and blocking
		// resistence by combining packets.
		coalescedBytes = 0
		coalesced := 1
		if s.clientInitMsg != nil {
			// Lazily send client init message with first data
			copy(coalesceBuffer, s.clientInitMsg)
			coalescedBytes += clientInitSize
			coalesced++
			s.clientInitMsg = nil
		}
		bufferFrame(frame)
	coalesceLoop:
		for coalescedBytes < coalesceThreshold {
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
			log.Tracef("Coalesced %d for total of %d", coalesced, coalescedBytes)
		}

		if coalesced == 1 && coalescedBytes < coalesceThreshold {
			// Add random padding whenever we failed to coalesce
			randLength, randErr := rand.Int(rand.Reader, s.maxPadding)
			if randErr != nil {
				s.onSessionError(nil, randErr)
				return
			}
			if log.IsTraceEnabled() {
				log.Tracef("Adding random padding of length: %d", randLength.Int64())
			}
			binaryEncoding.PutUint16(randomPadding[headerSize:], uint16(randLength.Int64()))
			coalesce(randomPadding[:fullHeaderSize+int(randLength.Int64())])
		}

		// Write coalesced data out
		_, err := s.Write(coalesceBuffer[:coalescedBytes])
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

func (s *session) getOrCreateStream(id uint16) (*stream, bool) {
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

	defaultHeader := newHeader(frameTypeData, id)
	c = &stream{
		Conn:    s,
		session: s,
		pool:    s.pool,
		rb:      newReceiveBuffer(defaultHeader, s.out, s.pool, s.windowSize),
		sb:      newSendBuffer(defaultHeader, s.out, s.windowSize),
	}
	s.streams[id] = c
	s.mx.Unlock()
	if s.connCh != nil {
		s.connCh <- c
	}
	return c, true
}

func (s *session) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	s.decrypt(b[:n])
	return n, err
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
