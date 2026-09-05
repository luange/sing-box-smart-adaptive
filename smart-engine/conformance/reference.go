package conformance

import "math"

// This file is the Go reference mirror of smart-engine/src/scoring.zig and
// the cold-start ranking/confirmation flow of policy.zig (interactive
// profile). Any change to the Zig kernel formula MUST be mirrored here; the
// conformance tests pin the two implementations to identical scores.

type Candidate struct {
	ID, State, Eligible                                                           uint64
	Reliability, ConnectMS, FirstByteMS, JitterMS, ThroughputBPS, Samples, Weight float64
}

type Config struct {
	Exploration, SwitchMargin         float64
	SwitchConfirmSamples              uint32
	SwitchConfirmMS, SwitchCooldownMS uint64
	MinSamples                        uint32
}

type Decision struct {
	SelectedID uint64
	Score      float64
	Switched   uint8
	Reason     uint8
}

type state struct {
	selected, challenge, since, cooldown uint64
	count                                uint32
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func normalizedCost(value, ceiling float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, -1) {
		return .5
	}
	if math.IsInf(value, 1) {
		return 1
	}
	if !(value > 0) {
		return .5
	}
	return math.Max(0, math.Min(1, math.Log1p(value)/math.Log1p(ceiling)))
}

func normalizedReliability(value float64) float64 {
	if !isFinite(value) {
		return .5
	}
	return math.Max(0, math.Min(1, value))
}

func weightOf(weight float64) float64 {
	if !(weight > 0) || !isFinite(weight) {
		return 1
	}
	if weight < 0.01 {
		return 0.01
	}
	return weight
}

func score(c Config, candidate Candidate, total float64) float64 {
	samples := 0.0
	if candidate.Samples > 0 && isFinite(candidate.Samples) {
		samples = candidate.Samples
	}
	exploration := 0.0
	if c.Exploration > 0 && isFinite(c.Exploration) {
		exploration = c.Exploration
	}
	reliability := normalizedReliability(candidate.Reliability)
	connect := normalizedCost(candidate.ConnectMS, 5000)
	first := normalizedCost(candidate.FirstByteMS, 10000)
	jitter := .5
	if candidate.ConnectMS > 0 && isFinite(candidate.ConnectMS) &&
		candidate.JitterMS >= 0 && isFinite(candidate.JitterMS) {
		jitter = math.Min(1, candidate.JitterMS/1000)
	}
	// The interactive profile keeps throughput_weight at 0 (scoring.zig);
	// ThroughputBPS is accepted for ABI compatibility but not ranked here.
	confidence := 0.0
	if samples < 3 {
		confidence = 1 - samples/3
	}
	base := .30*(1-reliability) + .25*connect + .30*first + .10*jitter + .05*confidence
	if candidate.State == 5 {
		base += 0.20
	}
	if samples > 0 && total > 0 {
		exploration *= math.Sqrt(math.Log(total+2) / (samples + 1))
	}
	return math.Max(0, base-exploration) / weightOf(candidate.Weight)
}

func choose(s *state, c Config, candidates []Candidate, now uint64) Decision {
	d := Decision{Score: 100, Reason: 3}
	var best *Candidate
	bestScore, total := math.Inf(1), 0.0
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID != 0 && candidate.Eligible != 0 && candidate.State != 4 {
			if candidate.Samples > 0 && isFinite(candidate.Samples) {
				total += candidate.Samples
			}
		}
	}
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID == 0 || candidate.Eligible == 0 || candidate.State == 4 {
			continue
		}
		value := score(c, *candidate, total)
		if isFinite(value) && (best == nil || value < bestScore) {
			best, bestScore = candidate, value
		}
	}
	if best == nil {
		return d
	}
	d.SelectedID, d.Score = best.ID, bestScore
	if s.selected == 0 || s.selected == best.ID {
		s.selected, d.Reason = best.ID, 0
		return d
	}
	for i := range candidates {
		if candidates[i].ID != s.selected {
			continue
		}
		currentScore := score(c, candidates[i], total)
		improvement := 0.0
		if currentScore > 0 {
			improvement = (currentScore - bestScore) / currentScore
		}
		if improvement < c.SwitchMargin || now < s.cooldown {
			d.SelectedID, d.Score, d.Reason = s.selected, currentScore, 1
			return d
		}
		break
	}
	if s.challenge != best.ID || s.since == 0 {
		s.challenge, s.count, s.since = best.ID, 1, now
		d.SelectedID, d.Reason = s.selected, 1
		return d
	}
	s.count++
	if s.count < c.SwitchConfirmSamples || now-s.since < c.SwitchConfirmMS {
		d.SelectedID, d.Reason = s.selected, 1
		return d
	}
	s.selected, s.cooldown = best.ID, now+c.SwitchCooldownMS
	s.challenge, s.count, s.since = 0, 0, 0
	d.SelectedID, d.Switched, d.Reason = best.ID, 1, 2
	return d
}
