package socks

import "bytes"

// Socks5AuthMethodRequest socks5代理认证方法请求
type Socks5AuthMethodRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

// Socks5AuthMethodResponse socks5认证方法结果
type Socks5AuthMethodResponse struct {
	Ver    byte
	Method byte
}

// Socks5ProxyRequest socks5代理请求明细结构
type Socks5ProxyRequest struct {
	Ver     byte
	Cmd     byte
	Rsv     byte
	Atyp    byte
	DstAddr []byte
	DstPort []byte
}

// Socks5ProxyResponse socks代理请求回应
type Socks5ProxyResponse struct {
	Ver     byte
	Rep     byte
	Rsv     byte
	Atyp    byte
	BndAddr []byte
	BndPort []byte
}

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
