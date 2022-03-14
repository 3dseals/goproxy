package proxy

import (
	"TCPProxy/crypto"
	"crypto/tls"
	"log"
	"net"
)

// Server is a TCP server that takes an incoming request and sends it to another
// server, proxying the response back to the client.
type Server struct {
	// TCP address to listen on
	Addr string

	// TCP address of target server
	Target string

	// ModifyRequest is an optional function that modifies the request from a client to the target server.
	ModifyRequest func(b *[]byte)

	// ModifyResponse is an optional function that modifies the response from the target server.
	ModifyResponse func(b *[]byte)

	// TLS configuration to listen on.
	TLSConfig *tls.Config

	// TLS configuration for the proxy if needed to connect to the target server with TLS protocol.
	// If nil, TCP protocol is used.
	TLSConfigTarget *tls.Config

	DESKey []byte

	//1 request encrypt and response decrypt
	//2 request decrypt and response encrypt
	DESMode int

	DESIv []byte

	BuffSize int

	EncodeBuffSize int
}

// ListenAndServe listens on the TCP network address laddr and then handle packets
// on incoming connections.
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.serve(listener)
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it uses TLS
// protocol. Additionally, files containing a certificate and matching private key
// for the server must be provided if neither the Server's TLSConfig.Certificates nor
// TLSConfig.GetCertificate are populated.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	configHasCert := len(s.TLSConfig.Certificates) > 0 || s.TLSConfig.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		var err error
		s.TLSConfig.Certificates = make([]tls.Certificate, 1)
		s.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}
	listener, err := tls.Listen("tcp", s.Addr, s.TLSConfig)
	if err != nil {
		return err
	}
	return s.serve(listener)
}

func (s *Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	// connects to target server
	var rconn net.Conn
	var err error
	if s.TLSConfigTarget == nil {
		rconn, err = net.Dial("tcp", s.Target)
	} else {
		rconn, err = tls.Dial("tcp", s.Target, s.TLSConfigTarget)
	}
	if err != nil {
		return
	}

	// write to dst what it reads from src
	var pipe = func(src, dst net.Conn, filter func(b *[]byte), encrypt bool, decrypt bool,  buffsize int) {
		defer func() {
			conn.Close()
			rconn.Close()
		}()

		buff := make([]byte, buffsize)
		for {
			n, err := src.Read(buff)
			if err != nil {
				log.Println(err)
				return
			}
			//log.Println(">>>>>>>>>>>>>>>>>接收消息>>>>>>>>>>>>>>>>>>>>>")
			//log.Println("input byte (" + strconv.Itoa(n) + ") : " + string(buff))
			b := buff[:n]
			if encrypt {
				b,_ = crypto.DesEncryption(s.DESKey, s.DESIv, buff[:n])
				//log.Println("1111111111111111111111加密转发1111111111111111111, len " + strconv.Itoa(len(b)))
				//log.Println("Encrypt byte (" + strconv.Itoa(len(b)) + ") : " + string(b))
			}
			if decrypt {
				b,_ = crypto.DesDecryption(s.DESKey, s.DESIv, b)
				//log.Println("222222222222222222222解密回传222222222222222222222")
				//log.Println("Decrypt byte (" + strconv.Itoa(len(b)) + ") : " + string(b))
			}
			//log.Println("<<<<<<<<<<<<<<<<<<<结束<<<<<<<<<<<<<<<<<<<<<<")
			//log.Println(".")
			//log.Println("..")
			//log.Println("...")

			if filter != nil {
				filter(&b)
			}

			_, err = dst.Write(b)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}

	lsize := s.BuffSize
	rsize := s.BuffSize
	if s.DESMode == 1 {
		lsize = s.BuffSize
		rsize = s.EncodeBuffSize
	}else if s.DESMode == 2 {
		lsize = s.EncodeBuffSize
		rsize = s.BuffSize
	}
	//本地发送到远程
	go pipe(conn, rconn, s.ModifyRequest, s.DESMode == 1, s.DESMode == 2, lsize)
	//从远程读取，返回本地
	go pipe(rconn, conn, s.ModifyResponse, s.DESMode == 2, s.DESMode == 1, rsize)
}
