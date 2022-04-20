package nns

import (
	"bytes"
	"errors"
	"github.com/bodgit/ntlmssp"
	"net"
	"time"
)

// NNSConn implements net.Conn interface and is an authenticated/"encrypted" NNS wrapped connection
type Conn struct {
	tcpConn    net.Conn
	secSession *ntlmssp.SecuritySession
	buffer     *bytes.Buffer
}

func (conn *Conn) Read(b []byte) (n int, err error) {
	if conn.buffer.Len() != 0 {
		//decrypted buffer not empty, keep sending bytes
		return conn.buffer.Read(b)
	}
	// empty, reset the buffer
	conn.buffer.Reset()
	// get nns encrypted packet
	nnsPacket, err := UnmarshalNNSPacket(conn.tcpConn)
	if err != nil {
		return 0, err
	}
	// get sig from first 16 bytes
	sig := nnsPacket.Payload[0:16]
	// get the payload
	encryptedPayload := nnsPacket.Payload[16:nnsPacket.Size]
	// decrypt the ntlmssp packet
	decrypted, err := conn.secSession.Unwrap(encryptedPayload, sig)
	if err != nil {
		return 0, err
	}
	// store in our buffer
	_, err = conn.buffer.Write(decrypted)
	// read into b buffer
	return conn.buffer.Read(b)
}

func (conn *Conn) Write(b []byte) (n int, err error) {
	encryptedPayload, sig, err := conn.secSession.Wrap(b)
	if err != nil {
		return 0, err
	}
	nnsPacket := DataPacket{
		Payload: append(sig, encryptedPayload...),
	}
	err = nnsPacket.WriteTo(conn.tcpConn)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (conn *Conn) Close() error {
	return conn.tcpConn.Close()
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.tcpConn.LocalAddr()
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.tcpConn.RemoteAddr()
}

func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.tcpConn.SetDeadline(t)
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.tcpConn.SetReadDeadline(t)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.tcpConn.SetWriteDeadline(t)
}

func DialNTLMSSP(address string, ntlmsspClient *ntlmssp.Client, timeout time.Duration) (conn net.Conn, err error) {
	if timeout > 0 {
		conn, err = net.DialTimeout("tcp", address, timeout)
	} else {
		conn, err = net.Dial("tcp", address)
	}
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	nego, err := ntlmsspClient.Authenticate(nil, nil)
	nnsAuthPacket := AuthPacket{
		MessageType: HandshakeInProgress,
		Payload:     nego,
	}
	if err != nil {
		return nil, err
	}
	err = nnsAuthPacket.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	nnsAuthPacket, err = UnmarshalAuthPacket(conn)
	if err != nil {
		return nil, err
	}
	ntlmSSPAuthPacket, err := ntlmsspClient.Authenticate(nnsAuthPacket.Payload, nil)
	nnsAuthPacket = AuthPacket{
		MessageType: HandshakeInProgress,
		Payload:     ntlmSSPAuthPacket,
	}
	err = nnsAuthPacket.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	nnsAuthPacket, err = UnmarshalAuthPacket(conn)
	if err != nil {
		return nil, err
	}
	if nnsAuthPacket.MessageType != HandshakeDone {
		return nil, AuthFailed
	}
	nnsConn := &Conn{
		tcpConn:    conn,
		secSession: ntlmsspClient.SecuritySession(),
		buffer:     bytes.NewBuffer([]byte{}),
	}
	//We're auth !
	return nnsConn, nil
}

var AuthFailed = errors.New("authentication failed")
