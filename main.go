package main

import (
	"flag"
	"fmt"
	"log"
)

// 主函数
func main() {
	// 解析命令行参数
	var ipAddr string
	var networkAddr string
	var help bool

	flag.StringVar(&ipAddr, "i", "", "指定IP地址")
	flag.StringVar(&networkAddr, "n", "", "指定网段 (例如: 192.168.1.0/24)")
	flag.BoolVar(&help, "help", false, "显示帮助信息")
	flag.Parse()

	// 显示帮助信息
	if help {
		fmt.Println("=== 网络探测工具 ===")
		fmt.Println("用法:")
		fmt.Println("  pingX.exe [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fmt.Println("  -i string      指定IP地址")
		fmt.Println("  -n string      指定网段 (例如: 192.168.1.0/24)")
		fmt.Println("  -help          显示帮助信息")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  pingX.exe -n 192.168.1.0/24")
		fmt.Println("  pingX.exe -i 192.168.1.1")
		return
	}

	// 处理用户指定的网络参数
	var target string
	var isSingleIP bool

	if networkAddr != "" {
		// 用户指定了网段，进行全网探测
		target = networkAddr
		isSingleIP = false
	} else if ipAddr != "" {
		// 用户指定了单个IP，只探测该IP
		target = ipAddr
		isSingleIP = true
	} else {
		// 用户没有指定参数，采用默认模式：获取本机IP和网段进行全网探测
		localIP, subnet, netAddr, err := getLocalIPAndSubnet()
		if err != nil {
			log.Fatalf("获取本机IP失败: %v", err)
		}
		target = netAddr
		isSingleIP = false
		fmt.Printf("=== 网络探测工具 ===\n")
		fmt.Printf("本机IP: %s\n", localIP)
		fmt.Printf("子网掩码: %s\n", subnet)
		fmt.Printf("网络地址: %s\n", target)
		fmt.Println()
	}

	// ICMP探测
	if isSingleIP {
		fmt.Printf("开始ICMP探测: %s...\n", target)
	} else {
		fmt.Printf("开始ICMP全网探测: %s...\n", target)
	}
	icmpResults, err := icmpScan(target)
	if err != nil {
		log.Fatalf("ICMP探测失败: %v", err)
	}
	fmt.Printf("ICMP探测完成，发现 %d 个活跃主机\n", len(icmpResults))
	fmt.Println()

	// 读取ARP缓存
	if isSingleIP {
		fmt.Printf("读取 %s 的ARP缓存信息...\n", target)
	} else {
		fmt.Println("读取本机ARP缓存...")
	}
	arpResults, err := readARPCache(target)
	if err != nil {
		fmt.Printf("读取ARP缓存失败: %v\n", err)
		arpResults = []DetectionResult{}
	} else {
		fmt.Printf("ARP缓存读取完成，发现 %d 个已缓存主机\n", len(arpResults))
	}
	fmt.Println()

	// 输出结果
	if err := writeResultToFile(icmpResults, arpResults, target); err != nil {
		log.Fatalf("写入结果文件失败: %v", err)
	}
}
