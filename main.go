package main

import "proxy_simple_implement/socks"

func main() {
	socksServer := &socks.Socks5ProxyServer{Port: 1080}
	socksServer.TCPServer()
}
