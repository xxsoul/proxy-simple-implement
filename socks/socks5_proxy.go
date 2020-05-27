package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

var (
	defaultEndian = binary.BigEndian
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
func (socksServer *Socks5ProxyServer) TCPServer() {
	log.Printf("socks5 proxy server start, listen port: %d", socksServer.Port)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: socksServer.Port})
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

		socksServer.handleTCPConnect(conn)
	}
}

// handleTCPConnect 处理TCP代理连接
func (socksServer *Socks5ProxyServer) handleTCPConnect(cliConn *net.TCPConn) {
	defer cliConn.Close() // 关闭连接

	remoteConn, err := socksServer.prepareProxyConnect(cliConn)
	if err != nil {
		log.Printf("prepare proxy connect error! msg is %s", err.Error())
		return
	}

	defer remoteConn.Close() //关闭远程连接，由于defer是压栈操作执行的，远程连接比代理连接先释放
	log.Printf("remote connect success, reday for exchange data")

	// 连接成功，准备交换数据

	cliReadChan := make(chan []byte)
	remoteReadChan := make(chan []byte)

	readFromCliFunc := func() {
		readBuf := make([]byte, socksServer.ReadBufLen) // 初始化一个32kb读缓冲区
		writeBuf := new(bytes.Buffer)

		for {
			readLen, readErr := cliConn.Read(readBuf)
			if readLen < 1 || readErr != nil {
				break
			}
			writeBuf.Write(readBuf[0:readLen])
			if readLen < socksServer.ReadBufLen {
				break
			}
			readBuf = readBuf[:0]
		}
		cliReadChan <- writeBuf.Bytes()
	}

	readFromRemoteFunc := func() {
		readBuf := make([]byte, socksServer.ReadBufLen) // 初始化一个32kb读缓冲区
		writeBuf := new(bytes.Buffer)

		for {
			readLen, readErr := remoteConn.Read(readBuf)
			if readLen < 1 || readErr != nil {
				break
			}
			writeBuf.Write(readBuf[0:readLen])
			if readLen < socksServer.ReadBufLen {
				break
			}
			readBuf = readBuf[:0]
		}
		remoteReadChan <- writeBuf.Bytes()
	}

	defer func() {
		close(remoteReadChan)
		close(cliReadChan)
	}()

	go readFromCliFunc()
	go readFromRemoteFunc()
conLoop:
	for {
		select {
		case buf, ok := <-cliReadChan:
			if !ok {
				log.Printf("client read channel closed")
			}

			c2rCount, c2rErr := remoteConn.Write(buf)
			if c2rErr != nil || c2rCount < 1 {
				log.Printf("data client -> remote exchange fail! msg is %s", err)
				break conLoop
			}
			log.Printf("data client -> remote exchange success! size is %d", c2rCount)
			go readFromCliFunc() // 重新读取
		case buf, ok := <-remoteReadChan:
			if !ok {
				log.Printf("remote read channel closed")
			}

			r2cCount, r2cErr := cliConn.Write(buf)
			if r2cErr != nil || r2cCount < 1 {
				log.Printf("data client <- remote exchange fail! msg is %s", err)
				break conLoop
			}
			log.Printf("data client <- remote exchange success! size is %d", r2cCount)
			go readFromRemoteFunc() // 重新读取
		}
	}

	log.Printf("proxy close")
}

// switchAuthMethod 选择合适的认证方法，版本默认为0x5，详细算法暂不实现
func (socksServer *Socks5ProxyServer) switchAuthMethod(authRequest Socks5AuthMethodRequest) Socks5AuthMethodResponse {
	return Socks5AuthMethodResponse{
		Ver:    0x05,
		Method: 0x00,
	}
}

// prepareProxyConnect 准备代理连接，包括了实际交换代理数据前的认证版本部分
func (socksServer *Socks5ProxyServer) prepareProxyConnect(cliConn *net.TCPConn) (net.Conn, error) {
	//连接建立后，客户端发送socks5版本认证请求
	log.Printf("begin handle proxy connect, ip is %s，begin auth version negotitate", cliConn.RemoteAddr().String())
	readBuf := make([]byte, 50)
	readBufCount, err := cliConn.Read(readBuf)
	if err != nil {
		return nil, err
	}
	authReq, err := verifyAuthMethodRequest(readBuf[:readBufCount])
	if err != nil {
		return nil, err
	}

	authRes := socksServer.switchAuthMethod(*(authReq))
	writeBuf := &bytes.Buffer{}
	binary.Write(writeBuf, defaultEndian, authRes) // 网络字节序通常为大端字节序，另外，这个方法不能用于写入字段中带切片的结构
	cliConn.Write(writeBuf.Bytes())

	log.Printf("auth version negotiate done! begin proxy detail request")
	readBuf = make([]byte, 200)
	readBufCount, err = cliConn.Read(readBuf)
	if err != nil {
		return nil, err
	}
	proxyReq, err := verifyProxyRequest(readBuf[:readBufCount])
	if err != nil {
		return nil, err
	}

	// 判断命令是否支持
	if proxyReq.Cmd != 0x01 {
		log.Printf("commend %x not implement", proxyReq.Cmd)
		proxyRes := Socks5ProxyResponse{
			Ver:  0x05,
			Rep:  0x07,
			Rsv:  0x00,
			Atyp: proxyReq.Atyp,
		}
		cliConn.Write(proxyRes.toByte())

		return nil, fmt.Errorf("commend %x not implement", proxyReq.Cmd)
	}

	remoteConn, remoteErr := socksServer.connectRemoteTCP(proxyReq)

	proxyRes := Socks5ProxyResponse{
		Ver:     0x05,
		Rsv:     0x00,
		Atyp:    proxyReq.Atyp,
		BndAddr: proxyReq.DstAddr,
		BndPort: proxyReq.DstPort,
	}
	if remoteErr != nil {
		proxyRes.Rep = 0x04
	} else {
		proxyRes.Rep = 0x00
	}

	// 回复proxyResponse
	cliConn.Write(proxyRes.toByte())

	return remoteConn, remoteErr
}

// connectRemoteTCP 使用tcp方式连接远程服务器
// todo: 需要考虑到如果下一步要连接的是二级代理该怎么办？
func (socksServer *Socks5ProxyServer) connectRemoteTCP(proxyReq *Socks5ProxyRequest) (net.Conn, error) {
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
	remoteConn, err := net.Dial("tcp", addres)
	if err != nil {
		return nil, err
	}
	return remoteConn, err
}
