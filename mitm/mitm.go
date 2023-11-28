// Package mitm implements a MITM attack on the SEMS portal protocol in order
// to extract metrics.
package mitm

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/lithammer/shortuuid/v4"
	"github.com/smlx/goodwe"
)

const (
	// semsportal server endpoint
	upstreamHost = "tcp.goodwe-power.com:20001"
	// network timeouts
	listenTimeout = 2 * time.Second
	readTimeout   = time.Second
	connTimeout   = 8 * time.Second
)

var (
	// packet frames start with these prefixes depending on direction
	outboundPrefix = []byte("POSTGW")
	inboundPrefix  = []byte("GW")

	// fixed AES key
	key = []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	// Inbound keepalive(?) occasionally sent by the server.
	// Note that this is not encrypted.
	keepAlive = []byte{0x01, 0x02}
)

// Timestamp is a time representation.
// TZ appears to be China Standard Time, AKA Beijing time (+08:00).
type Timestamp [6]byte

// Time returns a time.Time representation of t.
func (t *Timestamp) Time() time.Time {
	return time.Date(2000+int(t[0]), time.Month(t[1]),
		int(t[2]), int(t[3]), int(t[4]), int(t[5]), 0,
		time.FixedZone("+08", 8*60*60))
}

// PacketHandler is an interface implemented by both outbound and inbound
// packet handlers.
type PacketHandler interface {
	HandlePacket(context.Context, *slog.Logger, []byte) ([]byte, error)
}

// decryptCiphertext decrypts the given ciphertext using the fixed key.
func decryptCiphertext(iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%16 != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct new cipher: %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	cleartext := make([]byte, len(ciphertext))
	mode.CryptBlocks(cleartext, ciphertext)
	return cleartext, nil
}

// encryptCleartext decrypts the given ciphertext using the fixed key.
// This function does no padding - the cleartext length must be a multiple of
// blocksize.
func encryptCleartext(iv, cleartext []byte) ([]byte, error) {
	if len(cleartext)%16 != 0 {
		return nil, fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct new cipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(cleartext))
	mode.CryptBlocks(ciphertext, cleartext)
	return ciphertext, nil
}

// validateCRC checks that the Modbus CRC of the given data is correct. It
// assumes the expected CRC is the last two bytes of data.
func validateCRC(data []byte, bo binary.ByteOrder) error {
	crcVal := bo.Uint16(data[len(data)-2:])
	expectedCRCVal := goodwe.CRC(data[:len(data)-2])
	if expectedCRCVal != crcVal {
		return fmt.Errorf("CRC mismatch: expected %v, got %v", expectedCRCVal, crcVal)
	}
	return nil
}

// readPacket reads a full packet from r, using the header length immediately
// after the prefix to know how much to read.
func readPacket(r *bufio.Reader, prefix []byte) ([]byte, error) {
	headerLen := len(prefix) + 4 // prefix + 4 byte int32 packet length
	data, err := r.Peek(headerLen)
	if err != nil {
		return nil, fmt.Errorf("couldn't peek packet header: %v", err)
	}
	packetLen :=
		int(binary.BigEndian.Uint32(data[len(prefix):])) + // length in header
			headerLen + // length of header itself
			2 + // CRC
			1 // off-by-one error in header length :-/
	return io.ReadAll(io.LimitReader(r, int64(packetLen)))
}

// handleConn intercepts traffic in one direction of a TCP connection.
func (s *Server) handleConn(
	ctx context.Context,
	log *slog.Logger,
	in net.Conn,
	out net.Conn,
	packetPrefix []byte,
	forwardOnError bool,
	ph PacketHandler,
) error {
	var reader = bufio.NewReader(in)
	var data, newData []byte
	for {
		if ctx.Err() != nil {
			return nil // context cancelled
		}
		if err := in.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("couldn't set read deadline: %v", err)
		}
		prefix, err := reader.Peek(len(packetPrefix))
		if err != nil {
			// handle read timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // reached deadline
			}
			// return wihtout error on closed socket
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
				log.Debug("read socket closed")
				return nil
			}
			// return without error if we are in teardown
			if errors.Is(ctx.Err(), context.Canceled) {
				log.Debug("context cancelled")
				return nil
			}
			return fmt.Errorf("couldn't read: %v", err)
		}
		switch {
		case slices.Equal(keepAlive, prefix):
			log.Debug("keepalive(?)")
			data = keepAlive
			if _, err = reader.Discard(len(data)); err != nil {
				log.Warn("couldn't discard keepalive", slog.Any("error", err))
			}
		case slices.Equal(packetPrefix, prefix):
			data, err = readPacket(reader, packetPrefix)
			if err != nil {
				log.Warn("couldn't read packet",
					slog.Any("data", data),
					slog.Any("error", err))
				// skip to next packet
				discard, err := reader.ReadBytes(packetPrefix[0])
				if err != nil {
					log.Debug("couldn't find next prefix",
						slog.Any("discard", discard),
						slog.Any("error", err))
				}
				if err = reader.UnreadByte(); err != nil {
					log.Debug("couldn't unread byte")
				}
				if !forwardOnError {
					continue // don't forward invalid data
				}
			}
			newData, err = ph.HandlePacket(ctx, log, data)
			if err != nil {
				// not a fatal error, since maybe we just don't handle the
				// packet correctly yet.
				log.Warn("couldn't handle packet",
					slog.Any("packet", data),
					slog.Any("error", err))
				if !forwardOnError {
					continue // don't forward packets with handling errors
				}
			}
			if newData != nil && s.batsignal {
				// mutate the packet to summon batman to the SEMS Portal
				data = newData
			}
		default:
			log.Warn("unknown prefix", slog.Any("prefix", prefix))
			// skip to next packet
			if discard, err := reader.ReadBytes(packetPrefix[0]); err != nil {
				log.Debug("couldn't find next prefix",
					slog.Any("discard", discard),
					slog.Any("error", err))
			}
			if err = reader.UnreadByte(); err != nil {
				log.Debug("couldn't unread byte")
			}
			if !forwardOnError {
				continue // don't forward unrecognized packets
			}
		}
		// forward traffic
		_, err = out.Write(data)
		if err != nil {
			return fmt.Errorf("couldn't write out: %v", err)
		}
	}
}

// Server implements the MITM server.
type Server struct {
	batsignal bool
}

// NewServer constructs a new Server.
func NewServer(batsignal bool) *Server {
	return &Server{
		batsignal: batsignal,
	}
}

// Serve starts the sniff server.
func (s *Server) Serve(ctx context.Context, log *slog.Logger) error {
	if s.batsignal {
		setupBatsignal()
	}
	// make an outbound connection upstream as per a regular Goodwe device
	upstreamAddr, err := net.ResolveTCPAddr("tcp4", upstreamHost)
	if err != nil {
		return fmt.Errorf(`couldn't resolve "%s": %v`, upstreamHost, err)
	}
	// listen for an incoming connection from the local device
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 20001})
	if err != nil {
		return fmt.Errorf(`couldn't listen: %v`, err)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for {
		// break if ctx cancelled
		if listenCtx.Err() != nil {
			cancel()
			break
		}
		// accept incoming connections
		if err = listener.SetDeadline(time.Now().Add(listenTimeout)); err != nil {
			log.Error("couldn't set deadline on listener", slog.Any("error", err))
			cancel()
			break
		}
		conn, err := listener.Accept()
		if err != nil {
			// check if timeout reached
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Error("couldn't accept connection", slog.Any("error", err))
			cancel()
			break
		}
		// connect upstream
		outDialer := net.Dialer{Timeout: connTimeout}
		upstream, err := outDialer.DialContext(ctx, upstreamAddr.Network(),
			upstreamAddr.String())
		if err != nil {
			log.Error("couldn't dial upstream",
				slog.String("upstreamAddr", upstreamAddr.String()),
				slog.Any("error", err))
			conn.Close()
			continue
		}
		connLog := log.With(slog.Any("connID", shortuuid.New()))
		connLog.Debug("new outbound connection",
			slog.String("client", conn.RemoteAddr().String()))
		connCtx, cancel := context.WithCancel(listenCtx)
		// Handle duplex MITM connection in a pair of goroutines.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			defer upstream.Close()
			defer cancel()
			outboundLog := connLog.With(slog.String("direction", "outbound"))
			err := s.handleConn(connCtx, outboundLog, conn, upstream, outboundPrefix,
				true, NewOutboundPacketHandler(s.batsignal))
			if err != nil {
				outboundLog.Error("couldn't handle connection", slog.Any("error", err))
			}
			outboundLog.Debug("connection handler exiting")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			defer upstream.Close()
			defer cancel()
			inboundLog := connLog.With(slog.String("direction", "inbound"))
			err := s.handleConn(connCtx, inboundLog, upstream, conn, inboundPrefix,
				false, NewInboundPacketHandler())
			if err != nil {
				inboundLog.Error("couldn't handle connection", slog.Any("error", err))
			}
			inboundLog.Debug("connection handler exiting")
		}()
	}
	// wait for subprocessing to complete
	wg.Wait()
	return nil
}
