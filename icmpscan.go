package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMP探测功能
func icmpScan(network string) ([]DetectionResult, error) {
	// 获取网段中的所有IP地址
	ips, err := getIPsFromSubnet(network)
	if err != nil {
		return nil, fmt.Errorf("获取网段IP失败: %v", err)
	}

	var results []DetectionResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	ch := make(chan string, 30) // 并发线程数增加到30
	done := make(chan struct{}) // 用于通知接收协程退出的信号通道
	timeout := time.Second * 2

	// 创建ICMP连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("创建ICMP连接失败: %v", err)
	}
	defer conn.Close()

	// 发送ICMP请求的工作协程
	go func() {
		for ip := range ch {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()

				// 创建ICMP Echo Request
				msg := icmp.Message{
					Type: ipv4.ICMPTypeEcho, Code: 0,
					Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("hello")},
				}

				// 编码ICMP消息
				msgBytes, err := msg.Marshal(nil)
				if err != nil {
					return
				}

				// 发送ICMP消息
				_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: net.ParseIP(ip)})
				if err != nil {
					return
				}
			}(ip)
		}
	}()

	// 接收ICMP回复的工作协程
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-done: // 收到退出信号
				return
			default:
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// 超时，没有更多回复
						return
					}
					if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
						// 临时错误，继续尝试
						continue
					}
					// 其他错误，可能是连接已关闭
					return
				}

				// 解析ICMP消息
				msg, err := icmp.ParseMessage(1, buf[:n])
				if err != nil {
					continue
				}

				// 只处理Echo Reply
				if msg.Type == ipv4.ICMPTypeEchoReply {
					if echoBody, ok := msg.Body.(*icmp.Echo); ok && echoBody.ID == os.Getpid()&0xffff {
						// 使用addr参数获取源IP地址，更可靠
						srcIP := addr.(*net.IPAddr).IP.String()
						// 验证IP地址格式
						if net.ParseIP(srcIP) == nil {
							continue
						}
						// 实时显示结果
						fmt.Printf("[ICMP] 发现活跃主机: %s\n", srcIP)
						mu.Lock()
						results = append(results, DetectionResult{
							IP:     srcIP,
							MAC:    "未知",
							Status: "在线",
							Source: "ICMP",
						})
						mu.Unlock()
					}
				}
			}
		}
	}()

	// 发送所有IP地址到通道
	for _, ip := range ips {
		ch <- ip
		// 稍微延迟以避免网络拥塞
		time.Sleep(time.Millisecond * 10)
	}
	close(ch)

	// 等待所有发送协程完成
	wg.Wait()

	// 发送完所有请求后，设置读取超时，确保有完整的超时时间等待所有回复
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("设置连接超时失败: %v", err)
	}

	// 等待一段时间让所有回复到达
	time.Sleep(timeout)

	// 关闭信号通道，通知接收协程退出
	close(done)

	return results, nil
}
