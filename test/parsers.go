package e2e

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type PingStats struct {
	Min  float64
	Avg  float64
	Max  float64
	Mdev float64
}

var pingRTTRegex = regexp.MustCompile(`rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)

func ParsePingStats(output string) (*PingStats, error) {
	matches := pingRTTRegex.FindStringSubmatch(output)
	if matches == nil {
		return nil, fmt.Errorf("could not find RTT stats in ping output")
	}
	min, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse min RTT: %w", err)
	}
	avg, err := strconv.ParseFloat(matches[2], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse avg RTT: %w", err)
	}
	max, err := strconv.ParseFloat(matches[3], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse max RTT: %w", err)
	}
	mdev, err := strconv.ParseFloat(matches[4], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mdev RTT: %w", err)
	}
	return &PingStats{Min: min, Avg: avg, Max: max, Mdev: mdev}, nil
}

type DNSQueryTimes struct {
	Times []int
	Avg   float64
}

var digQueryTimeRegex = regexp.MustCompile(`Query time: (\d+) msec`)

func ParseDNSQueryTimes(output string) (*DNSQueryTimes, error) {
	matches := digQueryTimeRegex.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no query times found in dig output")
	}
	result := &DNSQueryTimes{}
	var total int
	for _, m := range matches {
		t, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse query time: %w", err)
		}
		result.Times = append(result.Times, t)
		total += t
	}
	result.Avg = float64(total) / float64(len(result.Times))
	return result, nil
}

func FormatMbps(bitsPerSecond float64) string {
	mbps := bitsPerSecond / 1e6
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", mbps), "0"), ".") + " Mbps"
}
