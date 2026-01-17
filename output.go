package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// 将探测结果写入TXT文件
func writeResultToFile(icmpResults, arpResults []DetectionResult, network string) error {
	// 使用固定文件名
	fileName := "aliver.txt"

	// 创建文件
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("创建结果文件失败: %v", err)
	}
	defer file.Close()

	// 判断是单个IP地址还是网段
	_, _, err = net.ParseCIDR(network)
	isSingleIP := (err != nil)

	// 写入文件头
	_, err = fmt.Fprintf(file, "=== 网络探测结果报告 ===\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "探测时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return err
	}
	if isSingleIP {
		_, err = fmt.Fprintf(file, "探测IP地址: %s\n", network)
	} else {
		_, err = fmt.Fprintf(file, "探测网段: %s\n", network)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "=======================\n\n")
	if err != nil {
		return err
	}

	// 写入ICMP探测结果
	_, err = fmt.Fprintf(file, "=== ICMP探测结果 ===\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "探测到 %d 个活跃主机\n\n", len(icmpResults))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "%-15s %-20s %-10s %-10s\n", "IP地址", "MAC地址", "状态", "来源")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "------------------------------------------------------\n")
	if err != nil {
		return err
	}

	// 对ICMP结果按IP排序
	sortResultsByIP(icmpResults)

	// 写入每个ICMP探测结果
	for _, result := range icmpResults {
		_, err = fmt.Fprintf(file, "%-15s %-20s %-10s %-10s\n", result.IP, result.MAC, result.Status, result.Source)
		if err != nil {
			return err
		}
	}

	// 写入ARP缓存结果
	_, err = fmt.Fprintf(file, "\n=== ARP缓存结果 ===\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "读取到 %d 个ARP缓存条目\n\n", len(arpResults))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "%-15s %-20s %-10s %-10s\n", "IP地址", "MAC地址", "状态", "来源")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "------------------------------------------------------\n")
	if err != nil {
		return err
	}

	// 对ARP结果按IP排序
	sortResultsByIP(arpResults)

	// 写入每个ARP缓存结果
	for _, result := range arpResults {
		_, err = fmt.Fprintf(file, "%-15s %-20s %-10s %-10s\n", result.IP, result.MAC, result.Status, result.Source)
		if err != nil {
			return err
		}
	}

	// 写入文件尾
	_, err = fmt.Fprintf(file, "\n=======================\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "报告生成完成！\n")
	if err != nil {
		return err
	}

	fmt.Printf("探测结果已保存到: %s\n", fileName)

	return nil
}
