package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

var ()

// Socks5ProxyServer socks5代理服务
// 简单实现，单线程，只监听0.0.0.0:port
type Socks5ProxyServer struct {
	Port int
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

	log.Printf("begin handle proxy connect, ip is %s，begin auth version negotitate", cliConn.RemoteAddr().String())

	//连接建立后，客户端发送socks5版本认证请求
	readBuf := make([]byte, 200)
	readBufCount, err := cliConn.Read(readBuf)
	if err != nil {
		log.Printf("read auth version error! msg is %s", err.Error())
		return
	}
	authReq, err := verifyAuthMethodRequest(readBuf[:readBufCount])
	if err != nil {
		log.Printf("verify auth method request error! msg is %s", err.Error())
		return
	}

	authRes := socksServer.switchAuthMethod(*(authReq))
	writeBuf := &bytes.Buffer{}
	binary.Write(writeBuf, binary.BigEndian, authRes) // 网络字节序通常为大端字节序
	cliConn.Write(writeBuf.Bytes())

	log.Printf("auth version negotiate done! begin proxy detail request")
	readBuf = make([]byte, 200)
	readBufCount, err = cliConn.Read(readBuf)
	if err != nil {
		log.Printf("read proxy request error! msg is %s", err.Error())
		return
	}
	proxyReq, err := verifyProxyRequest(readBuf[:readBufCount])
	if err != nil {
		log.Printf("verify proxy request request error! msg is %s", err.Error())
		return
	}

	if proxyReq.Cmd != 0x01 {
		log.Printf("commend %x not implement", proxyReq.Cmd)
		proxyRes := Socks5ProxyResponse{
			Ver:  0x05,
			Rep:  0x07,
			Rsv:  0x00,
			Atyp: proxyReq.Atyp,
		}

		writeBuf = &bytes.Buffer{}
		binary.Write(writeBuf, binary.BigEndian, proxyRes)
		cliConn.Write(writeBuf.Bytes())

		return
	}

	// 连接目标服务器
	addres := ""
	switch proxyReq.Atyp {
	case 0x01:
		addres = fmt.Sprintf("%s:%d", net.IPv4(proxyReq.DstAddr[0], proxyReq.DstAddr[1], proxyReq.DstAddr[2], proxyReq.DstAddr[3]).String(), binary.BigEndian.Uint16(proxyReq.DstPort))
	case 0x03:
		addres = fmt.Sprintf("%s:%d", string(proxyReq.DstAddr[1:]), binary.BigEndian.Uint16(proxyReq.DstPort))
	case 0x04:
		addres = fmt.Sprintf("[%s:%s:%s:%s:%s:%s:%s:%s]:%d",
			string(proxyReq.DstAddr[0:2]), string(proxyReq.DstAddr[2:4]),
			string(proxyReq.DstAddr[4:6]), string(proxyReq.DstAddr[6:8]),
			string(proxyReq.DstAddr[8:10]), string(proxyReq.DstAddr[10:12]),
			string(proxyReq.DstAddr[12:14]), string(proxyReq.DstAddr[14:16]), binary.BigEndian.Uint16(proxyReq.DstPort))
	}

	log.Printf("begin connect remote, addres is %s", addres)
	remoteConn, err := net.Dial("tcp", addres)
	if err != nil {
		log.Printf("remote connect fail, msg is %s", err.Error())
		return
	}
	defer remoteConn.Close() //关闭远程连接，由于defer是压栈操作执行的，远程连接比代理连接先释放
	log.Printf("remote connect success, reday for exchange data")
	// 连接成功，准备交换数据

	for cliReqBuf, err := ioutil.ReadAll(cliConn); err != nil && len(cliReqBuf) > 0; {
		// 收到客户端数据，转发到服务端
		_, rmtReqErr := remoteConn.Write(cliReqBuf)
		if rmtReqErr != nil {
			log.Printf("send data to remote fail! msg is %s", rmtReqErr.Error())
			break
		}

		rmtResDataBuf, rmtResErr := ioutil.ReadAll(remoteConn)
		if rmtResErr != nil || len(rmtResDataBuf) < 1 {
			errMsg := "nil"
			if rmtResErr != nil {
				errMsg = rmtResErr.Error()
			}
			log.Printf("receive response from remote fail or response length is 0! error msg is %s", errMsg)
			break
		}

		_, cliResErr := cliConn.Write(rmtResDataBuf)
		if cliResErr != nil {
			log.Printf("send response to client fail! msg is %s", cliResErr.Error())
			break
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
