package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// 读取ARP缓存
func readARPCache(network string) ([]DetectionResult, error) {
	// 执行arp -a命令
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行arp -a命令失败: %v", err)
	}

	// 解析输出结果
	results, err := parseARPCacheOutput(string(output), network)
	if err != nil {
		return nil, fmt.Errorf("解析ARP缓存输出失败: %v", err)
	}

	return results, nil
}

// 解析ARP缓存输出
func parseARPCacheOutput(output string, network string) ([]DetectionResult, error) {
	var results []DetectionResult

	// 尝试解析为CIDR格式的网段
	_, ipnet, err := net.ParseCIDR(network)
	var targetIP net.IP
	isSingleIP := false

	if err != nil {
		// 尝试解析为单个IP地址
		targetIP = net.ParseIP(network)
		if targetIP == nil || targetIP.To4() == nil {
			// 既不是CIDR格式也不是单个IP地址
			return nil, fmt.Errorf("无效的网络地址格式: %s", network)
		}
		isSingleIP = true
	}

	// 创建正则表达式用于匹配ARP缓存条目
	// 匹配格式: 192.168.1.1           00-11-22-33-44-55     动态
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\S+)$`)

	// 逐行读取输出
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// 使用正则表达式匹配
		match := re.FindStringSubmatch(line)
		if match != nil {
			ip := match[1]
			mac := match[2]
			status := match[3]

			// 检查IP地址是否匹配
			if isSingleIP {
				// 单个IP地址模式：只匹配指定的IP地址
				if net.ParseIP(ip).Equal(targetIP) {
					// 实时显示结果
					fmt.Printf("[ARP] 发现主机: %s  MAC: %s  状态: %s\n", ip, mac, status)
					results = append(results, DetectionResult{
						IP:     ip,
						MAC:    mac,
						Status: status,
						Source: "ARP缓存",
					})
				}
			} else {
				// 网段模式：匹配网段内的所有IP地址
				if ipnet.Contains(net.ParseIP(ip)) {
					// 实时显示结果
					fmt.Printf("[ARP] 发现主机: %s  MAC: %s  状态: %s\n", ip, mac, status)
					results = append(results, DetectionResult{
						IP:     ip,
						MAC:    mac,
						Status: status,
						Source: "ARP缓存",
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}
