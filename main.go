package main

import "proxy_simple_implement/socks"

func main() {
	socksServer := &socks.Socks5ProxyServer{
		Port:       1080,
		ReadBufLen: 65536, // 64kb读取缓冲区
	}
	socksServer.TCPServer()
}
