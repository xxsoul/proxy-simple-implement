package socks

import (
	"errors"
	"fmt"
)

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
