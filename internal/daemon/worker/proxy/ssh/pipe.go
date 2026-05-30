// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
)

// InterceptingConn wraps a net.Conn and intercepts SSH transport-layer messages.
// When a complete SSH message is read, it is parsed and emitted as a BSR chunk
// via the provided ConnectionRecorder. Raw byte data (channel data, etc.) is
// passed through transparently without chunk emission.
//
// This implements the Option B pipe architecture: SSH messages are parsed from
// the wire, non-data messages are converted to BSR chunks, and data messages
// (channel input/output) flow through plain io.Copy semantics.
type InterceptingConn struct {
	conn  net.Conn
	rec   *ConnectionRecorder
	dir   bsr.Direction
}

// newInterceptingConn creates a new intercepting connection wrapper.
func newInterceptingConn(conn net.Conn, rec *ConnectionRecorder, dir bsr.Direction) *InterceptingConn {
	return &InterceptingConn{
		conn: conn,
		rec:  rec,
		dir:  dir,
	}
}

// Read intercepts SSH messages and emits BSR chunks. It handles the SSH
// transport-layer framing: each message is preceded by a 4-byte big-endian
// length field.
//
// Returns:
//   - n > 0, err = nil: a non-data SSH message was parsed and emitted as a BSR
//     chunk; n is the number of bytes from the original wire message (passed
//     through to the caller for forwarding).
//   - err = io.EOF: connection closed cleanly.
//   - other err: read error.
func (ic *InterceptingConn) Read(p []byte) (n int, err error) {
	// Read the 4-byte SSH length header (RFC 4253).
	hdr := make([]byte, 4)
	_, err = io.ReadFull(ic.conn, hdr)
	if err != nil {
		return 0, err
	}
	packetLen := binary.BigEndian.Uint32(hdr)

	// SSH max packet size is 32768 bytes of payload + 64 bytes of padding.
	// Cap at a generous upper bound to prevent malformed input.
	const maxPacketLen = 35000 + 64
	if packetLen > maxPacketLen {
		return 0, errors.New("ssh: packet length exceeds maximum")
	}
	if packetLen > uint32(len(p)) {
		// Output buffer too small — this shouldn't happen with our 32 KiB pool.
		return 0, errors.New("ssh: output buffer too small for packet")
	}

	// Read the full packet payload.
	pkt := make([]byte, packetLen)
	_, err = io.ReadFull(ic.conn, pkt)
	if err != nil {
		return 0, err
	}

	// Copy header + packet into output buffer.
	n = 4 + int(packetLen)
	copy(p, hdr)
	copy(p[4:], pkt)

	// Parse the message type and emit BSR chunk.
	if ic.rec != nil {
		ic.emitChunk(pkt)
	}

	return n, nil
}

// emitChunk parses an SSH message payload and emits a BSR chunk if applicable.
// The payload starts at pkt[1:] (after the message type byte) since we already
// read the full packet including the type byte.
func (ic *InterceptingConn) emitChunk(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	msgType := pkt[0]
	payload := pkt[1:]

	switch msgType {
	case sshMsgChannelData, sshMsgChannelExtendedData:
		// Channel data: emit raw bytes as a DataChunk.
		// For CHANNEL_DATA: payload = uint32(channel_id) || data
		// For CHANNEL_EXTENDED_DATA: payload = uint32(channel_id) || uint32(data_type) || data
		var data []byte
		if msgType == sshMsgChannelData && len(payload) > 4 {
			data = payload[4:]
		} else if msgType == sshMsgChannelExtendedData && len(payload) > 8 {
			data = payload[8:]
		}
		if len(data) > 0 {
			_ = ic.rec.EmitDataChunk(ic.dir, data)
		}
		// No BSR structural chunk emitted for data messages.
		return

	default:
		// All other message types: emit the raw message as a DataChunk.
		// This captures the complete SSH message for playback without
		// requiring full proto parsing at record time.
		// TODO(ssh-recording-cycle5): Replace with per-message-type BSR chunks
		//   (SessionReq, PtyReq, ExecReq, etc.) once the EDTR chunk type is
		//   implemented. Currently deferred per researcher decision.
		_ = ic.rec.EmitDataChunk(ic.dir, pkt)
	}
}

// SSH message type numbers (RFC 4253).
const (
	sshMsgChannelData         = 94 // SSH_MSG_CHANNEL_DATA
	sshMsgChannelExtendedData = 95 // SSH_MSG_CHANNEL_EXTENDED_DATA
)

// Write proxies to the underlying connection.
func (ic *InterceptingConn) Write(p []byte) (n int, err error) {
	return ic.conn.Write(p)
}

// Close closes the underlying connection.
func (ic *InterceptingConn) Close() error {
	return ic.conn.Close()
}

// LocalAddr returns the underlying connection's local address.
func (ic *InterceptingConn) LocalAddr() net.Addr {
	return ic.conn.LocalAddr()
}

// RemoteAddr returns the underlying connection's remote address.
func (ic *InterceptingConn) RemoteAddr() net.Addr {
	return ic.conn.RemoteAddr()
}

// SetDeadline sets read/write deadlines on the underlying connection.
func (ic *InterceptingConn) SetDeadline(t time.Time) error {
	return ic.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (ic *InterceptingConn) SetReadDeadline(t time.Time) error {
	return ic.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (ic *InterceptingConn) SetWriteDeadline(t time.Time) error {
	return ic.conn.SetWriteDeadline(t)
}