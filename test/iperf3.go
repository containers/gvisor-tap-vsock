package e2e

import (
	"encoding/json"
	"fmt"
)

type Iperf3Stream struct {
	Bytes         int64   `json:"bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   int     `json:"retransmits"`
	LostPackets   int     `json:"lost_packets"`
	LostPercent   float64 `json:"lost_percent"`
}

type Iperf3Result struct {
	End struct {
		SumSent     Iperf3Stream `json:"sum_sent"`
		SumReceived Iperf3Stream `json:"sum_received"`
	} `json:"end"`
}

func ParseIperf3JSON(data []byte) (*Iperf3Result, error) {
	var result Iperf3Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse iperf3 JSON: %w", err)
	}
	return &result, nil
}
