package main

import (
	"fmt"
	"net"
)

// 存储探测结果的结构体
type DetectionResult struct {
	IP     string
	MAC    string
	Status string
	Source string
}

// 获取本机IP地址和网段信息
func getLocalIPAndSubnet() (string, string, string, error) {
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", "", err
	}

	for _, iface := range interfaces {
		// 跳过本地回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 跳过没有运行的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的IP地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// 只处理IPv4地址
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}

			// 返回IP地址、子网掩码和网络地址
			return ipnet.IP.String(), net.IP(ipnet.Mask).String(), ipnet.String(), nil
		}
	}

	return "", "", "", fmt.Errorf("未找到有效的网络接口")
}

// 计算广播地址
func calculateBroadcast(ipnet *net.IPNet) string {
	if ipnet == nil || ipnet.IP.To4() == nil {
		return ""
	}
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ipnet.IP.To4()[i] | ^ipnet.Mask[i]
	}
	return broadcast.String()
}

// 获取网段中的所有IP地址或单个IP地址
func getIPsFromSubnet(network string) ([]string, error) {
	// 尝试解析为CIDR格式的网段
	ip, ipnet, err := net.ParseCIDR(network)
	if err == nil {
		// 是CIDR格式的网段
		var ips []string
		// 创建一个可修改的IP副本
		currentIP := make(net.IP, len(ip.To4()))
		copy(currentIP, ip.To4())

		// 将currentIP设置为网络地址
		currentIP = currentIP.Mask(ipnet.Mask)

		for {
			// 创建IP副本以避免修改原始数据
			ipCopy := make(net.IP, len(currentIP))
			copy(ipCopy, currentIP)

			// 跳过网络地址和广播地址
			if !isNetworkAddress(ipCopy, ipnet) && !isBroadcastAddress(ipCopy, ipnet) {
				ips = append(ips, ipCopy.String())
			}

			// 递增IP地址
			inc(currentIP)

			// 检查是否已经超出网段范围
			if !ipnet.Contains(currentIP) {
				break
			}
		}

		return ips, nil
	}

	// 尝试解析为单个IP地址
	ip = net.ParseIP(network)
	if ip != nil && ip.To4() != nil {
		// 是单个IP地址
		return []string{ip.String()}, nil
	}

	// 既不是CIDR格式也不是单个IP地址
	return nil, fmt.Errorf("无效的网络地址格式: %s", network)
}

// 判断是否是网络地址
func isNetworkAddress(ip net.IP, ipnet *net.IPNet) bool {
	networkIP := ip.Mask(ipnet.Mask)
	return ip.Equal(networkIP)
}

// 判断是否是广播地址
func isBroadcastAddress(ip net.IP, ipnet *net.IPNet) bool {
	broadcast := calculateBroadcast(ipnet)
	return ip.String() == broadcast
}

// 递增IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 按IP地址对结果进行排序
func sortResultsByIP(results []DetectionResult) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if compareIP(results[i].IP, results[j].IP) > 0 {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

// 比较两个IP地址的大小
func compareIP(ip1, ip2 string) int {
	ipA := net.ParseIP(ip1).To4()
	ipB := net.ParseIP(ip2).To4()

	if ipA == nil || ipB == nil {
		return 0
	}

	for i := 0; i < 4; i++ {
		if ipA[i] != ipB[i] {
			return int(ipA[i]) - int(ipB[i])
		}
	}

	return 0
}
