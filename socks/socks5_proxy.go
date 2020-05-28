package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

		ss.handleProxyConnect(conn)
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

// doConnectCmd 执行socks的CONNECT命令
func (ss *Socks5ProxyServer) doConnectCmd(cliConn net.Conn, proxyReq Socks5ProxyRequest) (cmdErr error) {
	log.Printf("do connect from client %s", cliConn.RemoteAddr().String())
	proxyRes := Socks5ProxyResponse{
		Ver:     0x05,
		Rsv:     0x00,
		Atyp:    proxyReq.Atyp,
		BndAddr: proxyReq.DstAddr,
		BndPort: proxyReq.DstPort,
	}

	//建立远程连接
	remoteConn, remoteErr := ss.connectRemoteTCP(&proxyReq)
	if remoteErr != nil {
		proxyRes.Rep = 0x04
		cliConn.Write(proxyRes.toByte())
		return
	}
	// 回复proxyResponse
	proxyRes.Rep = 0x00
	cliConn.Write(proxyRes.toByte())

	defer remoteConn.Close() //关闭远程连接，由于defer是压栈操作执行的，远程连接比代理连接先释放
	log.Printf("remote connect success, reday for exchange data")

	// 连接成功，准备交换数据
	cliReadChan := make(chan bytes.Buffer)
	remoteReadChan := make(chan bytes.Buffer)

	go ss.readConnectToChannel(cliConn, cliReadChan)
	go ss.readConnectToChannel(remoteConn, remoteReadChan)
conLoop:
	for {
		select {
		case buf, ok := <-cliReadChan:
			if !ok {
				log.Printf("client read channel closed")
				break conLoop
			}

			c2rCount, c2rErr := remoteConn.Write(buf.Bytes())
			if c2rErr != nil {
				log.Printf("data client -> remote exchange fail! msg is %s", c2rErr)
				cmdErr = c2rErr
				break conLoop
			}
			log.Printf("data client -> remote exchange success! size is %d", c2rCount)
			// go readFromCliFunc()
			go ss.readConnectToChannel(cliConn, cliReadChan) // 重新读取
		case buf, ok := <-remoteReadChan:
			if !ok {
				log.Printf("remote read channel closed")
				break conLoop
			}

			r2cCount, r2cErr := cliConn.Write(buf.Bytes())
			if r2cErr != nil {
				log.Printf("data client <- remote exchange fail! msg is %s", r2cErr)
				cmdErr = r2cErr
				break conLoop
			}
			log.Printf("data client <- remote exchange success! size is %d", r2cCount)
			// go readFromRemoteFunc()
			go ss.readConnectToChannel(remoteConn, remoteReadChan) // 重新读取
		}
	}

	log.Printf("proxy close")
	return cmdErr
}

// connectRemoteTCP 使用tcp方式连接远程服务器
// todo: 需要考虑到如果下一步要连接的是二级代理该怎么办？
func (ss *Socks5ProxyServer) connectRemoteTCP(proxyReq *Socks5ProxyRequest) (*net.TCPConn, error) {
	// 连接目标服务器
	addres := ""
	switch proxyReq.Atyp {
	case 0x01:
		addres = fmt.Sprintf("%s:%d", net.IPv4(proxyReq.DstAddr[0], proxyReq.DstAddr[1], proxyReq.DstAddr[2], proxyReq.DstAddr[3]).String(), defaultEndian.Uint16(proxyReq.DstPort))
	case 0x03:
		addres = fmt.Sprintf("%s:%d", string(proxyReq.DstAddr[1:]), defaultEndian.Uint16(proxyReq.DstPort))
	case 0x04:
		addres = fmt.Sprintf("[%s:%s:%s:%s:%s:%s:%s:%s]:%d",
			string(proxyReq.DstAddr[0:2]), string(proxyReq.DstAddr[2:4]),
			string(proxyReq.DstAddr[4:6]), string(proxyReq.DstAddr[6:8]),
			string(proxyReq.DstAddr[8:10]), string(proxyReq.DstAddr[10:12]),
			string(proxyReq.DstAddr[12:14]), string(proxyReq.DstAddr[14:16]), defaultEndian.Uint16(proxyReq.DstPort))
	}

	log.Printf("begin connect remote, addres is %s", addres)
	remoteAddr, addrErr := net.ResolveTCPAddr("tcp4", addres)
	if addrErr != nil {
		return nil, addrErr
	}

	remoteConn, err := net.DialTCP("tcp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return remoteConn, err
}

// readConnectToChannel 从网络流中读取数据发送到channel中
func (ss *Socks5ProxyServer) readConnectToChannel(conn net.Conn, dataChan chan bytes.Buffer) {
	writeBuf, readErr := ss.readConnect(conn)

	if readErr != nil {
		close(dataChan) // 通过关闭channel，通知外部select结束
		return
	}

	dataChan <- *writeBuf
}

// readConnect 从流中读取数据，如果读取出错则关闭流通知调用方链接出错，将读取到的数据写入缓冲区并返回
func (ss *Socks5ProxyServer) readConnect(conn net.Conn) (*bytes.Buffer, error) {
	readBuf := make([]byte, ss.ReadBufLen)
	writeBuf := new(bytes.Buffer)

	for {
		readLen, readErr := conn.Read(readBuf)
		// 对于readErr!=nil，可以认为读取出错或链接被关闭，直接退出方法，其他情况一律拷贝流
		if readErr != nil {
			return nil, readErr
		}

		writeBuf.Write(readBuf[0:readLen])
		if readLen < ss.ReadBufLen {
			break
		}
		readBuf = readBuf[:0]
	}
	return writeBuf, nil
}
