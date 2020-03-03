package lampshade

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getlantern/ema"
	"github.com/getlantern/idletiming"
	"github.com/getlantern/mtime"
	"github.com/getlantern/ops"
)

var (
	ReadTimeout = 15 * time.Second
)

var (
	openSessions          int64
	closingSessions       int64
	closedSessions        int64
	openStreams           int64
	closingStreams        int64
	closingReceiveBuffers int64
	closingSendBuffers    int64
	closedStreams         int64
	recvLoops             int64
	sendLoops             int64
	trackStatsOnce        sync.Once
)

func trackStats() {
	trackStatsOnce.Do(func() {
		ops.Go(func() {
			for {
				time.Sleep(10 * time.Second)
				log.Debugf("Sessions    Open: %d   Closing: %d   Closed: %d   Recv Loops: %d   Send Loops: %d", atomic.LoadInt64(&openSessions), atomic.LoadInt64(&closingSessions), atomic.LoadInt64(&closedSessions), atomic.LoadInt64(&recvLoops), atomic.LoadInt64(&sendLoops))
				log.Debugf("Streams     Open: %d   Closing: %d   Closed: %d", atomic.LoadInt64(&openStreams), atomic.LoadInt64(&closingStreams), atomic.LoadInt64(&closedStreams))
				log.Debugf("Receive Buffers        Closing: %d", atomic.LoadInt64(&closingReceiveBuffers))
				log.Debugf("Send Buffers           Closing: %d", atomic.LoadInt64(&closingSendBuffers))
			}
		})
	})
}

type sessionIntf interface {
	AllowNewStream(maxStreamPerConn uint16, idleInterval time.Duration) bool
	MarkDefunct()
	CreateStream() *stream
}
type nullSession struct{}

func (s nullSession) AllowNewStream(maxStreamPerConn uint16, idleInterval time.Duration) bool {
	return false
}
func (s nullSession) MarkDefunct()          {}
func (s nullSession) CreateStream() *stream { panic("should never be called") }

// session encapsulates the multiplexing of streams onto a single "physical"
// net.Conn.
type session struct {
	net.Conn
	windowSize          int
	maxPadding          *big.Int
	paddingEnabled      bool
	cipherOverhead      int
	ackOnFirst          bool
	metaDecrypt         func([]byte) // decrypt in place
	metaEncrypt         func([]byte) // encrypt in place
	dataDecrypt         func([]byte) ([]byte, error)
	dataEncrypt         func(dst []byte, src []byte) []byte
	pool                BufferPool
	pingInterval        time.Duration
	lastPing            time.Time
	sendSessionFrame    []byte
	sendLengthBuffer    []byte
	out                 chan []byte
	echoOut             chan []byte
	streams             map[uint16]*stream
	closed              map[uint16]bool
	defunct             bool
	connCh              chan net.Conn
	beforeClose         func(*session)
	emaRTT              *ema.EMA
	closeCh             chan struct{}
	closeOnce           sync.Once
	finishedSendingCh   chan struct{}
	finishedReceivingCh chan struct{}
	lastDialed          time.Time
	nextID              uint32
	mx                  sync.RWMutex
}

// startSession starts a session on the given net.Conn using the given params.
// If connCh is provided, the session will notify of new streams as they are
// opened. If beforeClose is provided, the session will use it to notify when
// it's about to close. If clientInitMsg is provided, this message will be sent
// with the first frame sent in this session.
func startSession(conn net.Conn, windowSize int, maxPadding int, ackOnFirst bool, pingInterval time.Duration, cs *cryptoSpec, clientInitMsg []byte, pool BufferPool, emaRTT *ema.EMA, connCh chan net.Conn, beforeClose func(*session)) (*session, error) {
	s := &session{
		Conn:                conn,
		windowSize:          windowSize,
		maxPadding:          big.NewInt(int64(maxPadding)),
		paddingEnabled:      maxPadding > 0,
		ackOnFirst:          ackOnFirst,
		cipherOverhead:      cs.cipherCode.overhead(),
		pool:                pool,
		pingInterval:        pingInterval,
		lastPing:            time.Now(),
		sendSessionFrame:    make([]byte, maxSessionFrameSize), // Pre-allocate a sessionFrame for sending
		sendLengthBuffer:    make([]byte, lenSize),             // pre-allocate buffer for length to avoid extra allocations
		out:                 make(chan []byte),
		echoOut:             make(chan []byte),
		streams:             make(map[uint16]*stream),
		closed:              make(map[uint16]bool),
		emaRTT:              emaRTT,
		connCh:              connCh,
		beforeClose:         beforeClose,
		closeCh:             make(chan struct{}),
		finishedSendingCh:   make(chan struct{}),
		finishedReceivingCh: make(chan struct{}),
		lastDialed:          time.Now(), // to avoid new sessions being marked as idle.
	}
	var err error
	s.metaEncrypt, s.dataEncrypt, s.metaDecrypt, s.dataDecrypt, err = cs.crypters()
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&openSessions, 1)
	if clientInitMsg != nil {
		s.sendClientInitMsg(clientInitMsg)
	}
	ops.Go(s.sendLoop)
	ops.Go(s.recvLoop)
	return s, nil
}

func (s *session) sendClientInitMsg(clientInitMsg []byte) {
	// Client init message is already encrypted
	copy(s.sendSessionFrame, clientInitMsg)
	// send an empty frame with padding to randomize the size of the packet
	_, err := s.writeToWire(s.sendSessionFrame, clientInitSize+lenSize, 0, true)
	if err != nil {
		s.onSessionError(nil, err)
	}
}

func (s *session) recvLoop() {
	atomic.AddInt64(&recvLoops, 1)

	defer close(s.finishedReceivingCh)

	stoppedOnExpectedEOF := false

	defer func() {
		closeErr := s.Conn.Close()
		if closeErr != nil {
			if stoppedOnExpectedEOF && strings.Contains(closeErr.Error(), idletiming.ErrIdled.Error()) {
				// recvLoop stopped with an expected EOF caused by an idled connection.
				// Closing an idled connection is expected to fail, so don't bother
				// logging the error.
			} else {
				log.Errorf("Unexpected error closing underlying connection: %v", closeErr)
			}
		}
		atomic.AddInt64(&recvLoops, -1)
	}()

	alreadyLoggedReceiveForClosedStream := make(map[uint16]bool)

	echoTS := make([]byte, tsSize)
	lengthBuffer := make([]byte, lenSize)
	var sessionFrame []byte

	// Use a Reader that doesn't block indefinitely so that we can check for the
	// session being closed.
	r := idletiming.NewReader(s, ReadTimeout)

	readFull := func(b []byte) error {
		for {
			n, err := r.Read(b)
			if n == len(b) {
				return nil
			}
			if err != nil {
				return err
			}
			if s.isClosed() {
				log.Debug("recvLoop detected session closed")
				return io.EOF
			}
			b = b[n:]
		}
	}

	for {
		// First read and decrypt length
		err := readFull(lengthBuffer)
		if err != nil {
			if err == io.EOF {
				s.onSessionError(err, nil)
				stoppedOnExpectedEOF = true
			} else {
				s.onSessionError(fmt.Errorf("Unable to read length: %v", err), nil)
			}
			return
		}
		s.metaDecrypt(lengthBuffer)
		l := int(binaryEncoding.Uint16(lengthBuffer))

		// Then read the session frame
		if cap(sessionFrame) < l {
			sessionFrame = make([]byte, l)
		}
		sessionFrame = sessionFrame[:l]
		err = readFull(sessionFrame)
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

		first := true
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
				ackedFrames := b[headerSize:ackFrameSize]
				_, err = io.ReadFull(r, ackedFrames)
				if err != nil {
					s.onSessionError(err, nil)
					return
				}
				c.ack(int(binaryEncoding.Uint32(ackedFrames)))
				continue
			case frameTypeRST:
				// Closing existing connection
				s.mx.Lock()
				c := s.streams[id]
				s.closeStream(id)
				s.mx.Unlock()
				if c != nil {
					// Close, but don't send an RST back the other way since the other end is
					// already closed. Close on goroutine in case stream is blocked on
					// waiting for ACKs.
					go c.close(false, nil, nil)
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
				if !alreadyLoggedReceiveForClosedStream[id] {
					log.Debugf("Received data for closed stream %d", id)
					alreadyLoggedReceiveForClosedStream[id] = true
				}
				// Stream was already closed, ignore
				continue
			}
			c.rb.submit(b)

			if first {
				if s.ackOnFirst {
					// immediately send an empty ack to thwart timing attacks
					c.rb.doSendACK(0)
				}
				first = false
			}
		}
	}
}

func (s *session) sendLoop() {
	atomic.AddInt64(&sendLoops, 1)

	defer close(s.finishedSendingCh)

	defer func() {
		atomic.AddInt64(&sendLoops, -1)
	}()

	for {
		select {
		case <-s.closeCh:
			return
		case frame := <-s.out:
			if !s.send(frame) {
				// closed
				return
			}
		case frame := <-s.echoOut:
			// note - echos get their own channel so they don't queue behind data
			if !s.send(frame) {
				// closed
				return
			}
		}
	}
}

func (s *session) send(frame []byte) (open bool) {
	snd := &sender{
		session:        s,
		coalescedBytes: 0,
		coalesced:      0,
		startOfData:    lenSize, // Reserve space for header in sessionFrame
	}
	open = snd.send(frame)
	if len(snd.closedStreams) > 0 {
		s.mx.Lock()
		for _, streamID := range snd.closedStreams {
			s.closeStream(streamID)
		}
		s.mx.Unlock()
	}
	return
}

func (s *session) writeToWire(b []byte, startOfFrame, frameSize int, withPadding bool) (int, error) {
	startOfPadding := startOfFrame + frameSize
	if withPadding && startOfPadding < coalesceThreshold {
		l, err := s.addPadding(b[startOfPadding:])
		if err != nil {
			return 0, err
		}
		frameSize += l
	}

	framesData := b[startOfFrame : startOfFrame+frameSize]
	// Encrypt session frame with MAC appended
	encryptedFramesData := s.dataEncrypt(framesData, framesData)
	frameSize = len(encryptedFramesData)

	// Add length header before data
	lenBuf := b[startOfFrame-lenSize:]
	lenBuf = lenBuf[:lenSize]
	binaryEncoding.PutUint16(lenBuf, uint16(frameSize))
	s.metaEncrypt(lenBuf)

	return s.Write(b[:startOfFrame+frameSize])
}

// addPadding adds random sized padding to the byte slice. The size is capped
// by s.maxPadding and the slice length, whichever is lower. The slice is then
// zeroed out. It returns the padding size if there's no error.
func (s *session) addPadding(b []byte) (int, error) {
	if !s.paddingEnabled {
		return 0, nil
	}
	padding, err := rand.Int(rand.Reader, s.maxPadding)
	if err != nil {
		return 0, err
	}
	l := int(padding.Int64() + 1) // have at least 1 byte of padding
	if l > len(b) {
		l = len(b)
	}
	if log.IsTraceEnabled() {
		log.Tracef("Adding random padding of length: %d", l)
	}
	for i := 0; i < l; i++ {
		b[i] = 0
	}
	return l, nil
}

type sender struct {
	*session
	coalescedBytes int
	coalesced      int
	startOfData    int
	closedStreams  []uint16
}

func (snd *sender) send(frame []byte) (open bool) {
	// Coalesce pending writes. This helps with performance and blocking
	// resistence by combining packets.
	snd.bufferFrame(frame)
	open = snd.coalesceAdditionalFrames()

	if snd.pingInterval > 0 {
		snd.mx.Lock()
		now := time.Now()
		if now.Sub(snd.lastPing) > snd.pingInterval {
			snd.bufferFrame(ping())
			snd.lastPing = now
		}
		snd.mx.Unlock()
	}

	if log.IsTraceEnabled() {
		log.Tracef("Coalesced %d for total of %d", snd.coalesced, snd.coalescedBytes)
	}

	_, err := snd.writeToWire(snd.sendSessionFrame,
		snd.startOfData, snd.coalescedBytes,
		snd.coalesced == 1) // Add random padding whenever we failed to coalesce
	if err != nil {
		snd.onSessionError(nil, err)
	}
	return
}

func (snd *sender) coalesceAdditionalFrames() bool {
	// Coalesce enough to exceed coalesceThreshold
	for snd.startOfData+snd.coalescedBytes+snd.cipherOverhead < coalesceThreshold {
		select {
		case <-snd.closeCh:
			return false
		case frame := <-snd.out:
			// pending frame immediately available, add it
			snd.bufferFrame(frame)
		case frame := <-snd.echoOut:
			// pending echo immediately available, add it
			snd.bufferFrame(frame)
		default:
			// no more frames immediately available
			return true
		}
	}
	return true
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
	s.mx.RLock()
	numStreams := len(s.streams)
	s.mx.RUnlock()
	s.Close()

	if readErr == io.EOF && numStreams > 0 {
		// Treat EOF as ErrUnexpectedEOF because the underlying connection should
		// never be out of data until and unless the stream has been closed with an
		// RST frame.
		readErr = io.ErrUnexpectedEOF
	}

	if readErr == nil {
		readErr = syscall.EPIPE
	} else if readErr != io.EOF {
		log.Errorf("Error on reading from %v: %v", s.RemoteAddr(), readErr)
	}

	if writeErr == nil {
		writeErr = syscall.EPIPE
	} else {
		log.Errorf("Error on writing to %v: %v", s.RemoteAddr(), writeErr)
	}
}

func (s *session) CreateStream() *stream {
	nextID := atomic.AddUint32(&s.nextID, 1)
	stream, _ := s.getOrCreateStream(uint16(nextID - 1))
	s.lastDialed = time.Now()
	return stream
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

	c = newStream(s, s.pool, s.out, s.windowSize, newHeader(frameTypeData, id))
	s.streams[id] = c
	s.mx.Unlock()
	if s.connCh != nil {
		s.connCh <- c
	}
	return c, true
}

// AllowNewStream returns true if a new stream is allowed to be created over
// this session, and false otherwise.
func (s *session) AllowNewStream(maxStreamPerConn uint16, idleInterval time.Duration) bool {
	nextID := atomic.LoadUint32(&s.nextID)
	if nextID > uint32(maxStreamPerConn) {
		log.Debug("Exhausted maximum allowed IDs on one physical connection, will open new connection")
		return false
	}
	if idleInterval > 0 {
		now := time.Now()
		if now.Sub(s.lastDialed) > idleInterval {
			log.Debugf("No new connections in %v, will start new session", idleInterval)
			return false
		}
	}
	if s.isClosed() {
		return false
	}
	return true
}

// MarkDefunct marks this session as defunct. A defunct session will close once
// all streams are closed.
func (s *session) MarkDefunct() {
	s.mx.Lock()
	s.defunct = true
	if len(s.streams) == 0 {
		s.Close()
	}
	s.mx.Unlock()
}

func (s *session) closeStream(id uint16) {
	delete(s.streams, id)
	s.closed[id] = true
	if s.defunct && len(s.streams) == 0 {
		s.Close()
	}
}

var errorAlreadyClosed = errors.New("session already closed")

func (s *session) Close() error {
	err := errorAlreadyClosed
	s.closeOnce.Do(func() {
		close(s.closeCh)
		atomic.AddInt64(&closingSessions, 1)
		if s.beforeClose != nil {
			s.beforeClose(s)
		}
		atomic.AddInt64(&closingSessions, -1)
		atomic.AddInt64(&openSessions, -1)
		atomic.AddInt64(&closedSessions, 1)
		go func() {
			// wait until we're finished sending and receiving and then close any remaining streams
			<-s.finishedSendingCh
			<-s.finishedReceivingCh

			s.mx.RLock()
			for _, c := range s.streams {
				// Note - we never send an RST because the underlying connection is
				// considered no good at this point and we won't bother sending anything.
				go c.close(false, nil, nil)
			}
			s.mx.RUnlock()
		}()
		err = nil
	})
	return err
}

func (s *session) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

func (s *session) Wrapped() net.Conn {
	return s.Conn
}

// TODO: do we need a way to close a session/physical connection intentionally?
