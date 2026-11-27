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
		// UDP summary, the only one emitted for UDP by older iperf3 (e.g. iperf3-darwin).
		// It also carries the receiver-side lost_percent.
		Sum Iperf3Stream `json:"sum"`
	} `json:"end"`
}

func ParseIperf3JSON(data []byte) (*Iperf3Result, error) {
	var result Iperf3Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse iperf3 JSON: %w", err)
	}
	if result.End.SumSent.BitsPerSecond == 0 && result.End.Sum.BitsPerSecond == 0 {
		return nil, fmt.Errorf("no throughput summary found in iperf3 JSON")
	}
	return &result, nil
}
