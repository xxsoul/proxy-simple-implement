package socks

import (
	"bytes"
	"log"
	"net"
)

// doConnectCmd 执行socks协议CONNECT命令
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
	remoteConn, remoteErr := ss.connectRemoteTCP(proxyReq)
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

// doUDPAssociateCmd 指定socks协议UDPASSOCIATE命令，准备UDP中继
// 如果接入二级代理，则UDP中继服务该如何实现？
func (ss *Socks5ProxyServer) doUDPAssociateCmd(cliConn net.Conn, proxyReq Socks5ProxyRequest) (cmdErr error) {
	// 先准备UDP代理中继服务器，如果代理中继服务器准备失败则返回失败

	log.Printf("do UDPAssociate from client %s", cliConn.RemoteAddr().String())
	proxyRes := Socks5ProxyResponse{
		Ver:     0x05,
		Rsv:     0x00,
		Atyp:    proxyReq.Atyp,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00},
		BndPort: []byte{0x00, 0x00},
	}

	stopChan := make(chan int) // 中止标签

	//创建到目标的UDP连接
	remoteConn, remoteErr := ss.connectRemoteUDP(proxyReq)
	if remoteErr != nil {
		proxyRes.Rep = 0x04
		cliConn.Write(proxyRes.toByte())
		return
	}

	defer func() {
		stopChan <- 1
		remoteConn.Close()
	}()

	// 创建连接-中继服务的关联，启动中继服务，udp端口先写死
	relayFunc := func(cliConn net.Conn, proxyReq Socks5ProxyRequest) (bool, error) {
		_, udpErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 55643})
		if udpErr != nil {
			return false, udpErr
		}

	udpListen:
		for {
			select {
			case <-stopChan:
				break udpListen
			default:
				//udp中继器的逻辑
				// udpLn.ReadFrom()
			}
		}
		return true, nil
	}

	relayFunc(cliConn, proxyReq)

	return nil
}
