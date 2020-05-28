package socks

import (
	"bytes"
	"log"
	"net"
)

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
