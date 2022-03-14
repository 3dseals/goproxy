package main

import (
	"TCPProxy/proxy"
	"crypto/tls"
	"flag"
	"log"
	"unsafe"
)

var (
	// addresses
	localAddr  = flag.String("lhost", ":4433", "proxy local address")
	targetAddr = flag.String("rhost", ":80", "proxy remote address")
	desBuffSize = flag.Int("bufs", 4096, "proxy buff size")
	desMode = flag.Int("mode", 0, "proxy buff crypt mode")
	desKey  = flag.String("deskey", "", "des key for encrypt")

	// tls configuration for proxy as a server (listen)
	localTLS  = flag.Bool("ltls", false, "tls/ssl between client and proxy, you must set 'lcert' and 'lkey'")
	localCert = flag.String("lcert", "", "certificate file for proxy server side")
	localKey  = flag.String("lkey", "", "key x509 file for proxy server side")

	// tls configuration for proxy as a client (connection to target)
	targetTLS  = flag.Bool("rtls", false, "tls/ssl between proxy and target, you must set 'rcert' and 'rkey'")
	targetCert = flag.String("rcert", "", "certificate file for proxy client side")
	targetKey  = flag.String("rkey", "", "key x509 file for proxy client side")
)

func str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func main() {
	flag.Parse()

	p := proxy.Server{
		Addr:   *localAddr,
		Target: *targetAddr,
		DESMode: *desMode,
		DESKey: str2bytes(*desKey),
		DESIv: str2bytes("07758258"),
		BuffSize: *desBuffSize,
		EncodeBuffSize: *desBuffSize + 8,
	}

	if len(p.DESKey) !=0 && len(p.DESKey) !=8 {
		log.Println("des enKey length must be 8")
	}

	if *targetTLS {
		cert, err := tls.LoadX509KeyPair(*targetCert, *targetKey)
		if err != nil {
			log.Fatalf("configuration tls for target connection: %v", err)
		}
		p.TLSConfigTarget = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	}

	log.Println("Proxying from " + p.Addr + " to " + p.Target)
	if *localTLS {
		p.ListenAndServeTLS(*localCert, *localKey)
	} else {
		p.ListenAndServe()
	}
}
