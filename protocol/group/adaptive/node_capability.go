package adaptive

import (
	"strings"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// NodeCapabilityProfile is a process-local view of partial node availability.
// Unknown paths stay fail-open so a missing probe never hard-kills a family.
type NodeCapabilityProfile struct {
	TCP4      PathCapability `json:"tcp4"`
	TCP6      PathCapability `json:"tcp6"`
	DNSUDPv4  PathCapability `json:"dns_udp4"`
	DNSUDPv6  PathCapability `json:"dns_udp6"`
	DataUDPv4 PathCapability `json:"data_udp4"`
	DataUDPv6 PathCapability `json:"data_udp6"`
	Endpoint  PathCapability `json:"endpoint"`
	// ThroughputOK is true when the node has at least one trusted service
	// throughput sample above a conservative floor.
	ThroughputOK  bool    `json:"throughput_ok"`
	ThroughputBPS float64 `json:"throughput_bps,omitempty"`
}

type PathCapability struct {
	Path                string    `json:"path,omitempty"`
	Available           bool      `json:"available"`
	Known               bool      `json:"known"`
	Health              string    `json:"health,omitempty"`
	Breaker             string    `json:"breaker,omitempty"`
	SmoothedDelayMs     uint16    `json:"smoothed_delay_ms,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	RecoverySuccesses   int       `json:"recovery_successes,omitempty"`
	BackoffMs           uint32    `json:"backoff_ms,omitempty"`
	OpenUntil           time.Time `json:"open_until,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	LastFailure         string    `json:"last_failure,omitempty"`
}

func (s *HealthStore) BuildCapabilityProfile(handle NodeHandle, now time.Time) NodeCapabilityProfile {
	if now.IsZero() && s != nil && s.clock != nil {
		now = s.clock.Now()
	}
	profile := NodeCapabilityProfile{
		TCP4:      s.pathCapability(handle, "tcp/ipv4", now),
		TCP6:      s.pathCapability(handle, "tcp/ipv6", now),
		DNSUDPv4:  s.pathCapability(handle, "udp_dns/ipv4", now),
		DNSUDPv6:  s.pathCapability(handle, "udp_dns/ipv6", now),
		DataUDPv4: s.pathCapability(handle, "udp_data/ipv4", now),
		DataUDPv6: s.pathCapability(handle, "udp_data/ipv6", now),
		Endpoint:  s.pathCapability(handle, "", now),
	}
	return profile
}

func (s *HealthStore) pathCapability(handle NodeHandle, path string, now time.Time) PathCapability {
	cap := PathCapability{Path: path, Available: true}
	if s == nil {
		return cap
	}
	var status HealthStatus
	if path == "" {
		status = s.EndpointHandle(handle)
	} else {
		status = s.StatusHandle(handle, DomainTransport, path, "")
	}
	cap.Health = string(status.Health)
	cap.Breaker = string(status.Breaker)
	cap.SmoothedDelayMs = uint16(max(0, status.RankingDelay().Milliseconds()))
	cap.ConsecutiveFailures = status.ConsecutiveFailures
	cap.RecoverySuccesses = status.RecoverySuccesses
	cap.BackoffMs = uint32(max(0, status.Backoff.Milliseconds()))
	cap.OpenUntil = status.CooldownUntil
	cap.Reason = status.Reason
	if status.Health != HealthUnknown || status.Successes > 0 || status.Failures > 0 {
		cap.Known = true
	}
	// Mirror CanAttempt: open/cooldown are hard exclusions. Half-open after the
	// first recovery success remains eligible so confirmation traffic and
	// bounded production retries are not starved.
	switch status.Breaker {
	case BreakerOpen, BreakerCooldown:
		cap.Available = !status.CooldownUntil.IsZero() && !now.Before(status.CooldownUntil)
	default:
		if status.Health == HealthUnreachable && status.Breaker != BreakerHalfOpen {
			cap.Available = false
		}
	}
	if !cap.Available {
		if status.Reason != "" {
			cap.LastFailure = status.Reason
		} else if status.Breaker != BreakerClosed && status.Breaker != "" {
			cap.LastFailure = string(status.Breaker)
		} else {
			cap.LastFailure = string(status.Health)
		}
	} else if status.Breaker == BreakerHalfOpen && status.RecoverySuccesses < 2 {
		cap.LastFailure = "recovery_pending"
	}
	return cap
}

// ExplainExclusion returns a stable, non-sensitive reason when a candidate is
// filtered from a service plan. Empty means the candidate is eligible.
func (s *HealthStore) ExplainExclusion(handle NodeHandle, service ServiceContext, now time.Time) string {
	if s == nil {
		return ""
	}
	if now.IsZero() {
		now = s.clock.Now()
	}
	if !s.CanAttemptHandleReadOnly(handle, service, now) {
		endpoint := s.EndpointHandle(handle)
		if endpoint.Health == HealthUnreachable || endpoint.Breaker == BreakerOpen || endpoint.Breaker == BreakerCooldown || endpoint.Breaker == BreakerHalfOpen {
			return exclusionLabel("endpoint", endpoint)
		}
		transport := s.StatusHandle(handle, DomainTransport, serviceHealthTransport(service), "")
		if transport.Health == HealthUnreachable || transport.Breaker == BreakerOpen || transport.Breaker == BreakerCooldown || transport.Breaker == BreakerHalfOpen {
			return exclusionLabel(serviceHealthTransport(service), transport)
		}
		if service.ID != "" {
			serviceStatus := s.StatusHandle(handle, DomainService, "", service.ID)
			if serviceStatus.Health == HealthUnreachable || serviceStatus.Breaker == BreakerOpen || serviceStatus.Breaker == BreakerCooldown || serviceStatus.Breaker == BreakerHalfOpen {
				return exclusionLabel("service:"+service.ID, serviceStatus)
			}
		}
		return "path_unavailable"
	}
	return ""
}

func exclusionLabel(scope string, status HealthStatus) string {
	reason := status.Reason
	if reason == "" {
		if status.Breaker != BreakerClosed && status.Breaker != "" {
			reason = string(status.Breaker)
		} else {
			reason = string(status.Health)
		}
	}
	// Never include raw URLs or payloads; reason fields are already sanitized.
	reason = strings.TrimSpace(reason)
	if len(reason) > 96 {
		reason = reason[:96]
	}
	return scope + ":" + reason
}

// RequiredPathForService returns the health path that must be usable for this
// dial. Unknown/empty paths fail open.
func RequiredPathForService(service ServiceContext) string {
	return serviceHealthTransport(service)
}

// ProfileSupportsService reports whether the capability profile is known-bad
// for the service path. Unknown remains eligible (fail-open).
func (p NodeCapabilityProfile) SupportsService(service ServiceContext) (bool, string) {
	path := RequiredPathForService(service)
	cap := p.capabilityForPath(path)
	if !cap.Known {
		return true, ""
	}
	if !cap.Available {
		if cap.LastFailure != "" {
			return false, path + ":" + cap.LastFailure
		}
		return false, path + ":unavailable"
	}
	if service.Mode == ModeBulk && p.ThroughputBPS > 0 && !p.ThroughputOK {
		// Soft signal only; bulk mode still ranks by throughput elsewhere.
		return true, ""
	}
	return true, ""
}

func (p NodeCapabilityProfile) capabilityForPath(path string) PathCapability {
	switch path {
	case "tcp/ipv4":
		return p.TCP4
	case "tcp/ipv6":
		return p.TCP6
	case "udp_dns/ipv4":
		return p.DNSUDPv4
	case "udp_dns/ipv6":
		return p.DNSUDPv6
	case "udp_data/ipv4":
		return p.DataUDPv4
	case "udp_data/ipv6":
		return p.DataUDPv6
	case N.NetworkTCP, "tcp/any":
		// Prefer a known-good family; if either is known-bad and the other
		// unknown/good, still allow (destination family decides later).
		if p.TCP4.Known && p.TCP4.Available {
			return p.TCP4
		}
		if p.TCP6.Known && p.TCP6.Available {
			return p.TCP6
		}
		if p.TCP4.Known && !p.TCP4.Available && p.TCP6.Known && !p.TCP6.Available {
			return p.TCP4
		}
		return PathCapability{Path: path, Available: true}
	case N.NetworkUDP, "udp/any", "udp_data/any":
		if p.DataUDPv4.Known && p.DataUDPv4.Available {
			return p.DataUDPv4
		}
		if p.DataUDPv6.Known && p.DataUDPv6.Available {
			return p.DataUDPv6
		}
		if p.DataUDPv4.Known && !p.DataUDPv4.Available && p.DataUDPv6.Known && !p.DataUDPv6.Available {
			return p.DataUDPv4
		}
		return PathCapability{Path: path, Available: true}
	case "udp_dns/any":
		if p.DNSUDPv4.Known && p.DNSUDPv4.Available {
			return p.DNSUDPv4
		}
		if p.DNSUDPv6.Known && p.DNSUDPv6.Available {
			return p.DNSUDPv6
		}
		return PathCapability{Path: path, Available: true}
	default:
		return PathCapability{Path: path, Available: true}
	}
}
