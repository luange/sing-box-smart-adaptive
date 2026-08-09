//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"runtime"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

const (
	runtimeStatsInitialInterval = 30 * time.Second
	runtimeStatsInterval        = 5 * time.Minute
)

func (i *Inbound) startRuntimeStatsMonitor(backend *ECommon.Backend) {
	if i.statsCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.statsCancel = cancel
	i.statsDone = done
	go i.monitorRuntimeStats(ctx, done, backend)
}

func (i *Inbound) stopRuntimeStatsMonitor() {
	if i.statsCancel == nil {
		return
	}
	i.statsCancel()
	<-i.statsDone
	i.statsCancel = nil
	i.statsDone = nil
}

func (i *Inbound) monitorRuntimeStats(ctx context.Context, done chan<- struct{}, backend *ECommon.Backend) {
	defer close(done)
	timer := time.NewTimer(runtimeStatsInitialInterval)
	defer timer.Stop()
	initialSample := true
	var lastStats ECommon.RuntimeStats
	var lastSharedStats ECommon.SharedNetworkRuntimeStats
	var lastSpliceStats ECommon.SpliceStats
	var lastVerdictStats ECommon.VerdictStats
	var haveVerdictSample bool
	var haveSpliceSample bool
	var tcpWarningLevel int
	var udpWarningLevel int
	for {
		select {
		case <-ctx.Done():
			stats, err := backend.RuntimeStats()
			if err == nil {
				i.logRuntimeStats("final", stats, false)
			}
			i.logSharedRuntimeStats("final", false)
			i.logSpliceRuntimeStats("final", false)
			i.logVerdictRuntimeStats("final", false)
			i.logUDPNATMemoryStats("final")
			return
		case <-timer.C:
			reason := "periodic"
			if initialSample {
				reason = "initial"
				initialSample = false
			}
			stats, err := backend.RuntimeStats()
			if err == nil && stats != lastStats {
				tcpLevel := redirectMapWarningLevel(stats.TCPRedirectEntries, ECommon.TCPRedirectMapCapacity)
				udpLevel := redirectMapWarningLevel(stats.UDPRedirectEntries, ECommon.UDPRedirectMapCapacity)
				shouldWarn := stats.RedirectDrops > lastStats.RedirectDrops ||
					stats.LookupMisses > lastStats.LookupMisses ||
					tcpLevel > tcpWarningLevel || udpLevel > udpWarningLevel
				i.logRuntimeStats(reason, stats, shouldWarn)
				lastStats = stats
				if tcpLevel > tcpWarningLevel {
					tcpWarningLevel = tcpLevel
				}
				if udpLevel > udpWarningLevel {
					udpWarningLevel = udpLevel
				}
			}
			if i.sharedNetwork != nil && i.sharedNetwork.backend != nil {
				sharedStats, sharedErr := i.sharedNetwork.backend.RuntimeStats()
				if sharedErr == nil && sharedStats != lastSharedStats {
					warning := sharedStats.EgressReverseMisses > lastSharedStats.EgressReverseMisses ||
						sharedStats.TokenFailures > lastSharedStats.TokenFailures ||
						sharedStats.RewriteFailures > lastSharedStats.RewriteFailures ||
						sharedStats.SocketAssignFailures > lastSharedStats.SocketAssignFailures ||
						sharedStats.FlowUpdateFailures > lastSharedStats.FlowUpdateFailures
					i.logSharedRuntimeStatsValue(reason, sharedStats, warning)
					lastSharedStats = sharedStats
				}
			}
			if spliceStats, ok := i.spliceRuntimeStats(); ok {
				// Q12: first sample Info; failure increments → Warn (event-driven).
				failInc := spliceStats.RedirectFailures > lastSpliceStats.RedirectFailures ||
					spliceStats.PeerMisses > lastSpliceStats.PeerMisses
				if !haveSpliceSample || spliceStats != lastSpliceStats {
					warn := failInc
					if !haveSpliceSample {
						// promote initial to Info via reason rewrite below
						i.logSpliceRuntimeStatsValue("initial", spliceStats, warn)
						haveSpliceSample = true
					} else {
						i.logSpliceRuntimeStatsValue(reason, spliceStats, warn)
					}
					lastSpliceStats = spliceStats
				}
			}
			// A2/F-5: always emit first sample when verdict is on (even if all zeros),
			// then on any change — zeros-only would otherwise never log.
			if vStats, ok := i.verdictRuntimeStats(); ok {
				if !haveVerdictSample || vStats != lastVerdictStats {
					warn := vStats.GenMismatch > lastVerdictStats.GenMismatch
					i.logVerdictRuntimeStatsValue(reason, vStats, warn)
					lastVerdictStats = vStats
					haveVerdictSample = true
				}
			}
			i.logUDPNATMemoryStats(reason)
			timer.Reset(runtimeStatsInterval)
		}
	}
}

func (i *Inbound) logUDPNATMemoryStats(reason string) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	dataSessions, dnsSessions := 0, 0
	sharedDataSessions, sharedDNSSessions := 0, 0
	if i.udpNat != nil {
		dataSessions = i.udpNat.Len()
	}
	if i.dnsUDPNat != nil {
		dnsSessions = i.dnsUDPNat.Len()
	}
	if i.sharedNetwork != nil {
		if i.sharedNetwork.udpNat != nil {
			sharedDataSessions = i.sharedNetwork.udpNat.Len()
		}
		if i.sharedNetwork.dnsUDPNat != nil {
			sharedDNSSessions = i.sharedNetwork.dnsUDPNat.Len()
		}
	}
	i.logger.Info("eBPF userspace metrics: reason=", reason,
		", udp_sessions={data:", dataSessions,
		", dns:", dnsSessions,
		", shared_data:", sharedDataSessions,
		", shared_dns:", sharedDNSSessions,
		"}, goroutines=", runtime.NumGoroutine(),
		", heap_alloc=", memory.HeapAlloc)
}

func (i *Inbound) verdictRuntimeStats() (ECommon.VerdictStats, bool) {
	if i == nil || i.outboundCoord == nil {
		return ECommon.VerdictStats{}, false
	}
	backend := i.outboundCoord.Verdict()
	if backend == nil {
		return ECommon.VerdictStats{}, false
	}
	return backend.Stats(), true
}

func (i *Inbound) logVerdictRuntimeStats(reason string, warning bool) {
	stats, ok := i.verdictRuntimeStats()
	if !ok {
		return
	}
	i.logVerdictRuntimeStatsValue(reason, stats, warning)
}

func (i *Inbound) logVerdictRuntimeStatsValue(reason string, stats ECommon.VerdictStats, warning bool) {
	i.gcPromotedBypass()
	logArgs := []any{
		"eBPF outbound verdict metrics: reason=", reason,
		", writes=", stats.Writes,
		", skips=", stats.Skips,
		", kernel_hits=", stats.KernelHits,
		", expired=", stats.Expired,
		", gen_mismatch=", stats.GenMismatch,
	}
	if warning {
		i.logger.Warn(logArgs...)
	} else {
		i.logger.Info(logArgs...)
	}
	if i.outboundCoord != nil {
		sr := i.outboundCoord.SkipReasonSnapshot()
		// 2=sniff/matchInputs 3=non-direct 4=process 5=nodest 7=addr-mismatch
		i.logger.Info("eBPF verdict learn skip reasons: sniff/match=", sr[2],
			" non_direct=", sr[3], " process=", sr[4], " no_dest=", sr[5],
			" addr_mismatch=", sr[7])
		bare, typ, recvq, active := i.outboundCoord.SpliceSkipSnapshot()
		i.logger.Info("eBPF splice skip tallies: bare_tcp=", bare,
			" type=", typ, " recvq=", recvq, " active_total=", active)
	}
}

func (i *Inbound) spliceRuntimeStats() (ECommon.SpliceStats, bool) {
	if i == nil || i.outboundCoord == nil {
		return ECommon.SpliceStats{}, false
	}
	backend := i.outboundCoord.Splice()
	if backend == nil || backend.IsClosed() {
		return ECommon.SpliceStats{}, false
	}
	stats, err := backend.RuntimeStats()
	if err != nil {
		// N8: do not confuse "metrics unavailable" with "splice off".
		if !i.spliceStatsErrLogged {
			i.logger.Warn("eBPF outbound splice metrics unavailable: ", err)
			i.spliceStatsErrLogged = true
		}
		return ECommon.SpliceStats{}, false
	}
	i.spliceStatsErrLogged = false
	return stats, true
}

func (i *Inbound) logSpliceRuntimeStats(reason string, warning bool) {
	stats, ok := i.spliceRuntimeStats()
	if !ok {
		return
	}
	i.logSpliceRuntimeStatsValue(reason, stats, warning)
}

func (i *Inbound) logSpliceRuntimeStatsValue(reason string, stats ECommon.SpliceStats, warning bool) {
	logArgs := []any{
		"eBPF outbound splice metrics: reason=", reason,
		", pairs={created:", stats.PairsCreated,
		", released:", stats.PairsReleased,
		", active:", stats.ActivePairs,
		"}, redirects=", stats.Redirects,
		", redirect_failures=", stats.RedirectFailures,
		", peer_misses=", stats.PeerMisses,
		", passthrough=", stats.Passthrough,
	}
	// Q12: first sample + final + failure increments at Info/Warn; quiet periodic stays Debug.
	if warning {
		i.logger.Warn(logArgs...)
	} else if reason == "final" || reason == "initial" {
		i.logger.Info(logArgs...)
	} else {
		i.logger.Debug(logArgs...)
	}
}

func (i *Inbound) logSharedRuntimeStats(reason string, warning bool) {
	if i.sharedNetwork == nil || i.sharedNetwork.backend == nil {
		return
	}
	stats, err := i.sharedNetwork.backend.RuntimeStats()
	if err == nil {
		i.logSharedRuntimeStatsValue(reason, stats, warning)
	}
}

func (i *Inbound) logSharedRuntimeStatsValue(
	reason string,
	stats ECommon.SharedNetworkRuntimeStats,
	warning bool,
) {
	logArgs := []any{
		"eBPF shared-network metrics: reason=", reason,
		", ingress={redirects:", stats.IngressRedirects,
		", bypass:", stats.IngressBypass,
		", drops:", stats.IngressDrops,
		"}, egress={restores:", stats.EgressRestores,
		", reverse_misses:", stats.EgressReverseMisses,
		"}, token_failures=", stats.TokenFailures,
		", rewrite_failures=", stats.RewriteFailures,
		", socket_assign={success:", stats.SocketAssignments,
		", failures:", stats.SocketAssignFailures,
		", flow_update_failures:", stats.FlowUpdateFailures,
		"}",
	}
	if warning {
		i.logger.Warn(logArgs...)
	} else if reason == "final" || reason == "initial" {
		i.logger.Info(logArgs...)
	} else {
		i.logger.Debug(logArgs...)
	}
}

func redirectMapWarningLevel(entries uint64, capacity uint64) int {
	percentage := entries * 100 / capacity
	switch {
	case percentage >= 100:
		return 100
	case percentage >= 90:
		return 90
	case percentage >= 75:
		return 75
	default:
		return 0
	}
}

func (i *Inbound) logRuntimeStats(reason string, stats ECommon.RuntimeStats, warning bool) {
	logArgs := []any{
		"eBPF runtime metrics: reason=", reason,
		", redirect_map={tcp_entries:", stats.TCPRedirectEntries,
		", tcp_capacity:", ECommon.TCPRedirectMapCapacity,
		", udp_entries:", stats.UDPRedirectEntries,
		", udp_capacity:", ECommon.UDPRedirectMapCapacity,
		", token_collisions:", stats.TokenCollisions,
		", update_failures:", stats.MapUpdateFailures,
		", drops:", stats.RedirectDrops,
		"}, lookup_misses=", stats.LookupMisses,
	}
	if warning {
		i.logger.Warn(logArgs...)
	} else if reason == "final" || reason == "initial" {
		i.logger.Info(logArgs...)
	} else {
		i.logger.Debug(logArgs...)
	}
}
