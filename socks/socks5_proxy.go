package socks

import (
	"encoding/binary"
	"log"
	"net"
)

var (
	defaultEndian = binary.BigEndian // 网络字节序通常为大端字节序
)

// Socks5ProxyServer socks5代理服务
// 简单实现，单线程，只监听0.0.0.0:port
type Socks5ProxyServer struct {
	Port       int
	ReadBufLen int
}

// TCPServer 启动socks5TCP协议
// 1.端口监听
// 2.单线程处理单个请求，请求关闭前不处理其他代理请求
func (ss *Socks5ProxyServer) TCPServer() {
	log.Printf("socks5 proxy server start, listen port: %d", ss.Port)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: ss.Port})
	if err != nil {
		log.Printf("error!msg is %s", err.Error())
		return
	}

	defer ln.Close() // 结束之前，结束监听

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Printf("accept error!, msg is %s", err.Error())
		}

		go ss.handleProxyConnect(conn)
	}
}

// handleProxyConnect 处理代理请求，这个方法里包含了版本认证信息并选择对应的命令
func (ss *Socks5ProxyServer) handleProxyConnect(cliConn *net.TCPConn) {
	defer cliConn.Close()

	log.Printf("begin handle proxy connect, ip is %s，begin auth version negotitate", cliConn.RemoteAddr().String())
	authErr := ss.switchAuthMethod(cliConn)
	if authErr != nil {
		log.Printf("auth version negotitate failed! msg is %s ", authErr.Error())
		return
	}

	log.Printf("auth version negotiate done! begin proxy request")
	proxyReq, proxyErr := ss.obtainProxyRequest(cliConn)
	if proxyErr != nil {
		log.Printf("proxy request failed! msg is %s", proxyErr.Error())
		return
	}
	log.Printf("remote connect success, reday for exchange data")

	var cmdErr error
	switch proxyReq.Cmd {
	case 0x01:
		cmdErr = ss.doConnectCmd(cliConn, *proxyReq)
	}

	if cmdErr != nil {
		log.Printf("proxy closed with error! msg is %s", cmdErr.Error())
	}
}

// switchAuthMethod 选择合适的认证方法，版本默认为0x5，详细算法暂不实现
func (ss *Socks5ProxyServer) switchAuthMethod(cliConn net.Conn) error {
	//连接建立后，客户端发送socks5版本认证请求
	readBuf, readErr := ss.readConnect(cliConn)
	if readErr != nil {
		return readErr
	}
	_, verifyErr := verifyAuthMethodRequest(readBuf.Bytes())
	if verifyErr != nil {
		return verifyErr
	}

	authRes := Socks5AuthMethodResponse{
		Ver:    0x05,
		Method: 0x00,
	}
	authResByte := []byte{authRes.Ver, authRes.Method}
	_, authResErr := cliConn.Write(authResByte)
	return authResErr
}

// obtainProxyRequest 从流中获取代理请求信息
func (ss *Socks5ProxyServer) obtainProxyRequest(cliConn net.Conn) (*Socks5ProxyRequest, error) {
	readBuf, readErr := ss.readConnect(cliConn)
	if readErr != nil {
		return nil, readErr
	}
	proxyReq, proxyErr := verifyProxyRequest(readBuf.Bytes())
	if proxyErr != nil {
		return nil, proxyErr
	}
	return proxyReq, nil
}

// connectRemoteTCP 使用tcp方式连接远程服务器
// todo: 需要考虑到如果下一步要连接的是二级代理该怎么办？
func (ss *Socks5ProxyServer) connectRemoteTCP(proxyReq Socks5ProxyRequest) (*net.TCPConn, error) {
	// 连接目标服务器
	addres := resolveProxyRequestToAddr(proxyReq)

	log.Printf("begin connect remote tcp, addres is %s", addres)
	remoteAddr, addrErr := net.ResolveTCPAddr("tcp", addres)
	if addrErr != nil {
		return nil, addrErr
	}

	remoteConn, err := net.DialTCP("tcp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return remoteConn, err
}

// connectRemoteUDP 使用udp方式连接远程服务器
func (ss *Socks5ProxyServer) connectRemoteUDP(proxyReq Socks5ProxyRequest) (*net.UDPConn, error) {
	// 连接目标服务器
	addres := resolveProxyRequestToAddr(proxyReq)

	log.Printf("begin connect remote udp, addres is %s", addres)
	remoteAddr, addrErr := net.ResolveUDPAddr("udp", addres)
	if addrErr != nil {
		return nil, addrErr
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return remoteConn, err
}
