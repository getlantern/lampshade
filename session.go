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
	windowSize    int
	maxPadding    *big.Int
	metaDecrypt   func([]byte) // decrypt in place
	metaEncrypt   func([]byte) // encrypt in place
	dataDecrypt   func([]byte) ([]byte, error)
	dataEncrypt   func(dst []byte, src []byte) []byte
	clientInitMsg []byte
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

// startSession starts a session on the given net.Conn using the given params.
// If connCh is provided, the session will notify of new streams as they are
// opened. If beforeClose is provided, the session will use it to notify when
// it's about to close. If clientInitMsg is provided, this message will be sent
// with the first frame sent in this session.
func startSession(conn net.Conn, windowSize int, maxPadding int, pingInterval time.Duration, cs *cryptoSpec, clientInitMsg []byte, pool BufferPool, connCh chan net.Conn, beforeClose func(*session)) (*session, error) {
	s := &session{
		Conn:          conn,
		windowSize:    windowSize,
		maxPadding:    big.NewInt(int64(maxPadding)),
		clientInitMsg: clientInitMsg,
		pool:          pool,
		out:           make(chan []byte, windowSize*10), // TODO: maybe make this tunable
		echoOut:       make(chan []byte, 10),
		streams:       make(map[uint16]*stream),
		closed:        make(map[uint16]bool),
		connCh:        connCh,
		beforeClose:   beforeClose,
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
	go s.sendLoop(pingInterval)
	go s.recvLoop()
	return s, nil
}

func (s *session) recvLoop() {
	echoTS := make([]byte, tsSize)
	lb := make([]byte, 2)
	var sf []byte

	for {
		// First read and decrypt length
		_, err := io.ReadFull(s, lb)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to read length: %v", err), nil)
			return
		}
		s.metaDecrypt(lb)
		l := int(binaryEncoding.Uint16(lb))

		// Then read the session frame
		if cap(sf) < l {
			sf = make([]byte, l)
		}
		sf = sf[:l]
		_, err = io.ReadFull(s, sf)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to read session frame: %v", err), nil)
			return
		}

		// Decrypt session frame
		sf, err = s.dataDecrypt(sf)
		if err != nil {
			s.onSessionError(fmt.Errorf("Unable to decrypt session frame: %v", err), nil)
			return
		}

		r := bytes.NewReader(sf)

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

func (s *session) sendLoop(pingInterval time.Duration) {
	// Pre-allocate a sessionFrame
	sessionFrame := make([]byte, maxSessionFrameSize)
	coalescedBytes := 0
	startOfData := 2

	// pre-allocate buffer for length to avoid extra allocations
	lengthBuffer := make([]byte, lenSize)

	maxPadding := int(s.maxPadding.Int64())

	coalesce := func(b []byte) {
		copy(sessionFrame[startOfData+coalescedBytes:], b)
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
		// Reserve space for header in sessionFrame
		startOfData = 2

		// Coalesce pending writes. This helps with performance and blocking
		// resistence by combining packets.
		coalescedBytes = 0
		coalesced := 1
		if s.clientInitMsg != nil {
			// Lazily send client init message with first data, but don't encrypt
			copy(sessionFrame, s.clientInitMsg)
			startOfData = 2 + clientInitSize
			s.clientInitMsg = nil
		}
		bufferFrame(frame)

	coalesceLoop:
		// Coalesce as much as possible without exceeding maxSessionFrameSize
		for startOfData+coalescedBytes+maxHMACSize+maxFrameSize < maxSessionFrameSize {
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

		needsPadding := maxPadding > 0 && coalesced == 1 && coalescedBytes+startOfData < coalesceThreshold
		if needsPadding {
			// Add random padding whenever we failed to coalesce
			randLength, randErr := rand.Int(rand.Reader, s.maxPadding)
			if randErr != nil {
				s.onSessionError(nil, randErr)
				return
			}
			l := int(randLength.Int64())
			if log.IsTraceEnabled() {
				log.Tracef("Adding random padding of length: %d", l)
			}
			for i := startOfData + coalescedBytes; i < startOfData+coalescedBytes+l; i++ {
				// Zero out area of random padding
				sessionFrame[i] = 0
			}
			coalescedBytes += l
		}

		framesData := sessionFrame[startOfData : startOfData+coalescedBytes]
		// Encrypt session frame
		encryptedFramesData := s.dataEncrypt(framesData, framesData)
		coalescedBytes = len(encryptedFramesData)

		// Add length header
		lenBuf := sessionFrame[startOfData-2:]
		lenBuf = lenBuf[:2]
		binaryEncoding.PutUint16(lenBuf, uint16(coalescedBytes))
		s.metaEncrypt(lenBuf)

		// Write coalesced data out
		_, err := s.Write(sessionFrame[:startOfData+coalescedBytes])
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
