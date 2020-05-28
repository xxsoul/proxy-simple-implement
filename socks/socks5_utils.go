package socks

import (
	"bytes"
	"errors"
	"fmt"
	"net"
)

// toByte Socks5ProxyResponse结构体序列化为[]byte
func (proxyRes Socks5ProxyResponse) toByte() []byte {
	proxyResBuf := &bytes.Buffer{}
	proxyResBuf.WriteByte(proxyRes.Ver)
	proxyResBuf.WriteByte(proxyRes.Rep)
	proxyResBuf.WriteByte(proxyRes.Rsv)
	proxyResBuf.WriteByte(proxyRes.Atyp)
	proxyResBuf.Write(proxyRes.BndAddr)
	proxyResBuf.Write(proxyRes.BndPort)

	return proxyResBuf.Bytes()
}

// verifyAuthMethodRequest 读取并校验给定的流（byte数组），解析为Socks5AuthMethodRequest*
func verifyAuthMethodRequest(buf []byte) (*Socks5AuthMethodRequest, error) {
	if len(buf) < 3 {
		return nil, errors.New("readed byte length illegal(less then 3)")
	}
	if buf[0] != 0x05 {
		return nil, errors.Unwrap(fmt.Errorf("readed version illeagal(version is %x not 0x5)", buf[0]))
	}

	req := Socks5AuthMethodRequest{}
	req.Ver = buf[0]
	req.NMethods = buf[1]
	req.Methods = make([]byte, int(req.NMethods))

	for i := 0; i < int(req.NMethods); i++ {
		req.Methods = append(req.Methods, buf[i+1])
	}

	return &req, nil
}

// verifyProxyRequest 读取并校验给定的流（byte数组），解析为Socks5ProxyRequest*
func verifyProxyRequest(buf []byte) (*Socks5ProxyRequest, error) {
	if len(buf) < 10 {
		return nil, errors.New("readed byte length illegal(less then 10)")
	}
	if buf[0] != 0x05 {
		return nil, errors.Unwrap(fmt.Errorf("readed version illeagal(version is %x not 0x5)", buf[0]))
	}

	req := Socks5ProxyRequest{}
	req.Ver = buf[0]
	req.Cmd = buf[1]
	req.Rsv = buf[2]
	req.Atyp = buf[3]
	seek := 0
	switch buf[3] {
	case 0x01:
		seek = 4
	case 0x03:
		seek = int(buf[4]) + 1
	case 0x04:
		seek = 16
	}
	req.DstAddr = buf[4 : 4+seek]
	req.DstPort = buf[4+seek:]

	return &req, nil
}

// resolveProxyRequestToAddr 解析代理请求中目标地址为字符串
func resolveProxyRequestToAddr(proxyReq Socks5ProxyRequest) string {
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

	return addres
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
