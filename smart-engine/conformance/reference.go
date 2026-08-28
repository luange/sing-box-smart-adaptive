package conformance

import "math"

type Candidate struct {
	ID, State, Eligible                                                           uint64
	Reliability, ConnectMS, FirstByteMS, JitterMS, ThroughputBPS, Samples, Weight float64
}

type Config struct {
	Exploration, SwitchMargin         float64
	SwitchConfirmSamples              uint32
	SwitchConfirmMS, SwitchCooldownMS uint64
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

func normalized(value, ceiling float64) float64 {
	if value <= 0 || math.IsNaN(value) {
		return .5
	}
	return math.Max(0, math.Min(1, math.Log1p(value)/math.Log1p(ceiling)))
}

func score(c Config, candidate Candidate, total float64) float64 {
	connect := normalized(candidate.ConnectMS, 5000)
	first := normalized(candidate.FirstByteMS, 10000)
	jitter := .5
	if candidate.JitterMS > 0 {
		jitter = math.Min(1, candidate.JitterMS/1000)
	}
	exploration := math.Max(c.Exploration, 0)
	if candidate.Samples > 0 && total > 0 {
		exploration *= math.Sqrt(math.Log(total+1) / candidate.Samples)
	}
	return math.Max(0, .45*(1-candidate.Reliability)+.30*connect+.15*first+.10*jitter-exploration) / math.Max(candidate.Weight, 1)
}

func choose(s *state, c Config, candidates []Candidate, now uint64) Decision {
	d := Decision{Score: 100, Reason: 3}
	var best *Candidate
	bestScore, total := 100.0, 0.0
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID != 0 && candidate.Eligible != 0 && candidate.State != 4 {
			total += math.Max(candidate.Samples, 0)
		}
	}
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID == 0 || candidate.Eligible == 0 || candidate.State == 4 {
			continue
		}
		value := score(c, *candidate, total)
		if best == nil || value < bestScore {
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
