package lampshade

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/getlantern/ema"
	"github.com/getlantern/mtime"
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
	isClient      bool
	pool          BufferPool
	out           chan []byte
	echoOut       chan []byte
	streams       map[uint16]*stream
	closed        map[uint16]bool
	connCh        chan net.Conn
	beforeClose   func(*session)
	emaRTT        *ema.EMA
	mx            sync.RWMutex
}

// startSession starts a session on the given net.Conn using the given transmit
// windowSize and pool. If connCh is provided, the session will notify of new
// streams as they are opened. If beforeClose is provided, the session will use
// it to notify when it's about to close. If clientInitMsg is provided, this
// message will be sent with the first frame sent in this session.
func startSession(conn net.Conn, windowSize int, maxPadding int, pingInterval time.Duration, decrypt func([]byte), encrypt func(dst []byte, src []byte), clientInitMsg []byte, pool BufferPool, connCh chan net.Conn, beforeClose func(*session)) *session {
	s := &session{
		Conn:          conn,
		windowSize:    windowSize,
		maxPadding:    big.NewInt(int64(maxPadding)),
		decrypt:       decrypt,
		encrypt:       encrypt,
		clientInitMsg: clientInitMsg,
		isClient:      clientInitMsg != nil,
		pool:          pool,
		out:           make(chan []byte),
		echoOut:       make(chan []byte, 10),
		streams:       make(map[uint16]*stream),
		closed:        make(map[uint16]bool),
		connCh:        connCh,
		beforeClose:   beforeClose,
	}
	if s.isClient {
		s.emaRTT = ema.NewDuration(0, 0.01) // use a low alpha to give old values influence
	}
	go s.sendLoop(pingInterval)
	go s.recvLoop()
	return s
}

func (s *session) recvLoop() {
	echoTS := make([]byte, tsSize)

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
			c, open, _ := s.getOrCreateStream(id)
			if !open {
				// Stream was already closed, ignore
				continue
			}
			_ackedFrames := b[headerSize:ackFrameSize]
			_, err = io.ReadFull(s, _ackedFrames)
			if err != nil {
				s.onSessionError(err, nil)
				return
			}
			ackedFrames := int(int32(binaryEncoding.Uint32(_ackedFrames)))
			c.sb.window.add(ackedFrames)
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
		case frameTypePing:
			e := echo()
			_, err = io.ReadFull(s, e[:tsSize])
			if err != nil {
				s.onSessionError(err, nil)
				return
			}
			s.echoOut <- e
			continue
		case frameTypeEcho:
			_, err = io.ReadFull(s, echoTS)
			if err != nil {
				s.onSessionError(err, nil)
				return
			}
			rtt := mtime.Now().Sub(mtime.Instant(binaryEncoding.Uint64(echoTS)))
			s.emaRTT.UpdateDuration(rtt)
			continue
		}

		// Read frame length
		_dataLength := b[headerSize:dataHeaderSize]
		_, err = io.ReadFull(s, _dataLength)
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		dataLength := int(binaryEncoding.Uint16(_dataLength))
		// Read frame
		b = b[:dataHeaderSize+dataLength]
		_, err = io.ReadFull(s, b[dataHeaderSize:])
		if err != nil {
			s.onSessionError(err, nil)
			return
		}

		if isPadding {
			// don't do anything with padding after we've read it
			continue
		}

		c, open, created := s.getOrCreateStream(id)
		if !open {
			// Stream was already closed, ignore
			continue
		}
		c.rb.submit(b)
		if created {
			// immediately send an empty ACK on newly created streams for timing
			c.rb.sendACK()
		}
	}
}

func (s *session) sendLoop(pingInterval time.Duration) {
	// Use maxFrameSize * 2 for coalesce buffer to avoid having to grow it
	coalesceBuffer := make([]byte, maxFrameSize*2)
	coalescedBytes := 0

	// pre-allocate buffer for length to avoid extra allocations
	lengthBuffer := make([]byte, lenSize)

	// pre-allocate empty buffer for random padding
	// note - we can use an empty buffer because after encryption with AES in CTR
	// mode it is effectively random anyway.
	maxPadding := int(s.maxPadding.Int64())
	randomPadding := make([]byte, dataHeaderSize+maxPadding)
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
		switch frameType(header) {
		case frameTypeRST:
			// RST frames only contain the header
			return
		case frameTypeACK, frameTypePing, frameTypeEcho:
			// ACK, ping and echo frames also have additional data
			coalesce(frame[:dataLen])
			return
		default:
			// data frame
			binaryEncoding.PutUint16(lengthBuffer, uint16(dataLen))
			coalesce(lengthBuffer)
			coalesce(frame[:dataLen])
			// Put frame back in pool
			s.pool.Put(frame[:maxFrameSize])
		}
	}

	lastPing := time.Now()

	onFrame := func(frame []byte) {
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
			case frame = <-s.echoOut:
				// pending echo immediately available, add it
				bufferFrame(frame)
				coalesced++
			default:
				// no more frames immediately available
				break coalesceLoop
			}
		}

		if pingInterval > 0 {
			now := time.Now()
			if now.Sub(lastPing) > pingInterval {
				bufferFrame(ping())
				coalesced++
				lastPing = now
			}
		}

		if log.IsTraceEnabled() {
			log.Tracef("Coalesced %d for total of %d", coalesced, coalescedBytes)
		}

		if maxPadding > 0 && coalesced == 1 && coalescedBytes < coalesceThreshold {
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
			coalesce(randomPadding[:dataHeaderSize+int(randLength.Int64())])
		}

		// Write coalesced data out
		_, err := s.Write(coalesceBuffer[:coalescedBytes])
		if err != nil {
			s.onSessionError(nil, err)
			return
		}
	}

	for {
		select {
		case frame, more := <-s.out:
			onFrame(frame)
			if !more {
				// closed
				return
			}
		case frame := <-s.echoOut:
			// note - echos get their own channel so they don't queue behind data
			onFrame(frame)
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

func (s *session) getOrCreateStream(id uint16) (c *stream, open bool, created bool) {
	s.mx.Lock()
	c = s.streams[id]
	if c != nil {
		s.mx.Unlock()
		return c, true, false
	}
	closed := s.closed[id]
	if closed {
		s.mx.Unlock()
		return nil, false, false
	}

	defaultHeader := newHeader(frameTypeData, id)
	c = &stream{
		Conn:    s,
		session: s,
		pool:    s.pool,
		sb:      newSendBuffer(defaultHeader, s.out, s.windowSize),
		rb:      newReceiveBuffer(defaultHeader, s.out, s.pool, s.windowSize),
	}
	s.streams[id] = c
	s.mx.Unlock()
	if s.connCh != nil {
		s.connCh <- c
	}
	return c, true, true
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

func (s *session) EMARTT() time.Duration {
	return s.emaRTT.GetDuration()
}

// TODO: do we need a way to close a session/physical connection intentionally?
