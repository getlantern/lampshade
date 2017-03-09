package lampshade

import (
	"bytes"
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

const (
	oneYear = 8760 * time.Hour
)

// session encapsulates the multiplexing of streams onto a single "physical"
// net.Conn.
type session struct {
	net.Conn
	windowSize       int
	maxPadding       *big.Int
	paddingEnabled   bool
	cipherOverhead   int
	metaDecrypt      func([]byte) // decrypt in place
	metaEncrypt      func([]byte) // encrypt in place
	dataDecrypt      func([]byte) ([]byte, error)
	dataEncrypt      func(dst []byte, src []byte) []byte
	clientInitMsg    []byte
	pool             BufferPool
	pingInterval     time.Duration
	lastPing         time.Time
	sendSessionFrame []byte
	sendLengthBuffer []byte
	out              chan []byte
	echoOut          chan []byte
	streams          map[uint16]*stream
	closed           map[uint16]bool
	connCh           chan net.Conn
	beforeClose      func(*session)
	emaRTT           *ema.EMA
	mx               sync.RWMutex
}

// startSession starts a session on the given net.Conn using the given params.
// If connCh is provided, the session will notify of new streams as they are
// opened. If beforeClose is provided, the session will use it to notify when
// it's about to close. If clientInitMsg is provided, this message will be sent
// with the first frame sent in this session.
func startSession(conn net.Conn, windowSize int, maxPadding int, pingInterval time.Duration, cs *cryptoSpec, clientInitMsg []byte, pool BufferPool, connCh chan net.Conn, beforeClose func(*session)) (*session, error) {
	s := &session{
		Conn:             conn,
		windowSize:       windowSize,
		maxPadding:       big.NewInt(int64(maxPadding)),
		paddingEnabled:   maxPadding > 0,
		cipherOverhead:   cs.cipherCode.overhead(),
		clientInitMsg:    clientInitMsg,
		pool:             pool,
		pingInterval:     pingInterval,
		lastPing:         time.Now(),
		sendSessionFrame: make([]byte, maxSessionFrameSize), // Pre-allocate a sessionFrame for sending
		sendLengthBuffer: make([]byte, lenSize),             // pre-allocate buffer for length to avoid extra allocations
		out:              make(chan []byte),
		echoOut:          make(chan []byte),
		streams:          make(map[uint16]*stream),
		closed:           make(map[uint16]bool),
		connCh:           connCh,
		beforeClose:      beforeClose,
	}
	var err error
	s.metaEncrypt, s.dataEncrypt, s.metaDecrypt, s.dataDecrypt, err = cs.crypters()
	if err != nil {
		return nil, err
	}
	isClient := clientInitMsg != nil
	if isClient {
		s.emaRTT = ema.NewDuration(0, 0.5)
	}
	go s.sendLoop()
	go s.recvLoop()
	return s, nil
}

func (s *session) recvLoop() {
	echoTS := make([]byte, tsSize)
	lengthBuffer := make([]byte, lenSize)
	var sessionFrame []byte

	for {
		// First read and decrypt length
		_, err := io.ReadFull(s, lengthBuffer)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to read length: %v", err), nil)
			return
		}
		s.metaDecrypt(lengthBuffer)
		l := int(binaryEncoding.Uint16(lengthBuffer))

		// Then read the session frame
		if cap(sessionFrame) < l {
			sessionFrame = make([]byte, l)
		}
		sessionFrame = sessionFrame[:l]
		_, err = io.ReadFull(s, sessionFrame)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to read session frame: %v", err), nil)
			return
		}

		// Decrypt session frame
		sessionFrame, err = s.dataDecrypt(sessionFrame)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to decrypt session frame: %v", err), nil)
			return
		}

		r := bytes.NewReader(sessionFrame)

		// Read stream frames
	frameLoop:
		for {
			b := s.pool.getForFrame()
			// First read header
			header := b[:headerSize]
			_, err := io.ReadFull(r, header)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					// We're done reading the session frame
					break frameLoop
				}
				s.onSessionError(fmt.Errorf("Unable to read header: %v", err), nil)
				return
			}

			frameType, id := frameTypeAndID(header)
			switch frameType {
			case frameTypePadding:
				// Padding is always at the end of a session frame, so stop processing
				break frameLoop
			case frameTypeACK:
				c, open := s.getOrCreateStream(id)
				if !open {
					// Stream was already closed, ignore
					continue
				}
				_ackedFrames := b[headerSize:ackFrameSize]
				_, err = io.ReadFull(r, _ackedFrames)
				if err != nil {
					s.onSessionError(err, nil)
					return
				}
				ackedFrames := int(binaryEncoding.Uint32(_ackedFrames))
				c.sb.window.add(ackedFrames)
				continue
			case frameTypeRST:
				// Closing existing connection
				s.mx.Lock()
				c := s.streams[id]
				s.closeStream(id)
				s.mx.Unlock()
				if c != nil {
					// Close, but don't send an RST back the other way since the other end is
					// already closed.
					c.close(false, nil, nil)
				}
				continue
			case frameTypePing:
				e := echo()
				_, err = io.ReadFull(r, e[:tsSize])
				if err != nil {
					s.onSessionError(err, nil)
					return
				}
				s.echoOut <- e
				continue
			case frameTypeEcho:
				_, err = io.ReadFull(r, echoTS)
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
			_, err = io.ReadFull(r, _dataLength)
			if err != nil {
				s.onSessionError(err, nil)
				return
			}

			dataLength := int(binaryEncoding.Uint16(_dataLength))
			// Read frame
			b = b[:dataHeaderSize+dataLength]
			_, err = io.ReadFull(r, b[dataHeaderSize:])
			if err != nil {
				s.onSessionError(err, nil)
				return
			}

			c, open := s.getOrCreateStream(id)
			if !open {
				// Stream was already closed, ignore
				continue
			}
			c.rb.submit(b)
		}
	}
}

func (s *session) sendLoop() {
	for {
		select {
		case frame, more := <-s.out:
			s.send(frame)
			if !more {
				// closed
				return
			}
		case frame := <-s.echoOut:
			// note - echos get their own channel so they don't queue behind data
			s.send(frame)
		}
	}
}

func (s *session) send(frame []byte) {
	snd := &sender{
		session:        s,
		coalescedBytes: 0,
		coalesced:      1,
		startOfData:    lenSize, // Reserve space for header in sessionFrame
	}
	snd.send(frame)
	if len(snd.closedStreams) > 0 {
		s.mx.Lock()
		for _, streamID := range snd.closedStreams {
			s.closeStream(streamID)
		}
		s.mx.Unlock()
	}
}

type sender struct {
	*session
	coalescedBytes int
	coalesced      int
	startOfData    int
	closedStreams  []uint16
}

func (snd *sender) send(frame []byte) {
	// Coalesce pending writes. This helps with performance and blocking
	// resistence by combining packets.
	if snd.clientInitMsg != nil {
		// Lazily send client init message with first data, but don't encrypt
		copy(snd.sendSessionFrame, snd.clientInitMsg)
		// Push start of data right
		snd.startOfData += clientInitSize
		snd.clientInitMsg = nil
	}
	snd.bufferFrame(frame)
	snd.coalesceAdditionalFrames()

	if snd.pingInterval > 0 {
		now := time.Now()
		if now.Sub(snd.lastPing) > snd.pingInterval {
			snd.bufferFrame(ping())
			snd.lastPing = now
		}
	}

	if log.IsTraceEnabled() {
		log.Tracef("Coalesced %d for total of %d", snd.coalesced, snd.coalescedBytes)
	}

	needsPadding := snd.paddingEnabled && snd.coalesced == 1 && snd.coalescedBytes+snd.startOfData < coalesceThreshold
	if needsPadding {
		// Add random padding whenever we failed to coalesce
		randLength, randErr := rand.Int(rand.Reader, snd.maxPadding)
		if randErr != nil {
			snd.onSessionError(nil, randErr)
			return
		}
		l := int(randLength.Int64())
		if log.IsTraceEnabled() {
			log.Tracef("Adding random padding of length: %d", l)
		}
		for i := snd.startOfData + snd.coalescedBytes; i < snd.startOfData+snd.coalescedBytes+l; i++ {
			// Zero out area of random padding
			snd.sendSessionFrame[i] = 0
		}
		snd.coalescedBytes += l
	}

	framesData := snd.sendSessionFrame[snd.startOfData : snd.startOfData+snd.coalescedBytes]
	// Encrypt session frame
	encryptedFramesData := snd.dataEncrypt(framesData, framesData)
	snd.coalescedBytes = len(encryptedFramesData)

	// Add length header before data
	lenBuf := snd.sendSessionFrame[snd.startOfData-lenSize:]
	lenBuf = lenBuf[:lenSize]
	binaryEncoding.PutUint16(lenBuf, uint16(snd.coalescedBytes))
	snd.metaEncrypt(lenBuf)

	// Write session frame to wire
	_, err := snd.Write(snd.sendSessionFrame[:snd.startOfData+snd.coalescedBytes])
	if err != nil {
		snd.onSessionError(nil, err)
	}
}

func (snd *sender) coalesceAdditionalFrames() {
	// Coalesce enough to exceed coalesceThreshold
	for snd.startOfData+snd.coalescedBytes+snd.cipherOverhead < coalesceThreshold {
		select {
		case frame := <-snd.out:
			// pending frame immediately available, add it
			snd.bufferFrame(frame)
		case frame := <-snd.echoOut:
			// pending echo immediately available, add it
			snd.bufferFrame(frame)
		default:
			// no more frames immediately available
			return
		}
	}
}

func (snd *sender) bufferFrame(frame []byte) {
	snd.coalesced++
	dataLen := len(frame) - headerSize
	if dataLen > MaxDataLen {
		panic(fmt.Sprintf("Data length of %d exceeds maximum allowed of %d", dataLen, MaxDataLen))
	}
	header := frame[dataLen:]
	snd.coalesce(header)
	frameType, streamID := frameTypeAndID(header)
	switch frameType {
	case frameTypeRST:
		// RST frames only contain the header
		snd.closedStreams = append(snd.closedStreams, streamID)
		return
	case frameTypeACK, frameTypePing, frameTypeEcho:
		// ACK, ping and echo frames also have additional data
		snd.coalesce(frame[:dataLen])
		return
	default:
		// data frame
		binaryEncoding.PutUint16(snd.sendLengthBuffer, uint16(dataLen))
		snd.coalesce(snd.sendLengthBuffer)
		snd.coalesce(frame[:dataLen])
		// Put frame back in pool
		snd.pool.Put(frame[:maxFrameSize])
	}
}

func (snd *sender) coalesce(b []byte) {
	copy(snd.sendSessionFrame[snd.startOfData+snd.coalescedBytes:], b)
	snd.coalescedBytes += len(b)
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
		Conn:       s,
		session:    s,
		pool:       s.pool,
		sb:         newSendBuffer(defaultHeader, s.out, s.windowSize),
		rb:         newReceiveBuffer(defaultHeader, s.out, s.pool, s.windowSize),
		writeTimer: time.NewTimer(oneYear),
	}
	s.streams[id] = c
	s.mx.Unlock()
	if s.connCh != nil {
		s.connCh <- c
	}
	return c, true
}

func (s *session) closeStream(id uint16) {
	delete(s.streams, id)
	s.closed[id] = true
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
