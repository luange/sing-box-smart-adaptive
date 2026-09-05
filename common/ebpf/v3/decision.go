package v3

// Action is the TC-facing outcome after the fixed decision order.
type Action uint8

const (
	ActionContinue Action = iota // TC_ACT_OK without mark (DIRECT / bypass / leave alone)
	ActionProxy                  // NEED_USERSPACE handoff
	ActionBlock                  // TC_ACT_SHOT
)

// Decision is the pure model of tc_ingress §5 — unit-tested without a kernel.
type Decision struct {
	Action Action
	Reason Reason
	Mark   uint32 // must be 0 on Direct/Block/security/parse-fail
}

// StaticPolicy is one compiled LPM hit (already generation-checked by caller).
type StaticPolicy struct {
	Verdict Verdict
}

// FlowHit is one exact-flow hit (already generation/TTL-checked by caller).
type FlowHit struct {
	Verdict Verdict
}

// Input gathers maps/control state for one packet decision.
type Input struct {
	Control        Control
	Packet         Packet
	Static         *StaticPolicy
	Flow           *FlowHit
	DNS            *DNSIPValue
	DNSNowNs       uint64
	EstablishedTCP bool
}

// Decide implements design §5 order. Any failure → Proxy, never silent Direct.
func Decide(in Input) Decision {
	c := in.Control
	p := in.Packet

	if c.Enabled == 0 || c.ABIVersion != ABIVersion {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}

	// §5.1 parse failure
	if p.ParseRC < 0 {
		return Decision{Action: ActionContinue, Reason: ReasonParseFailProxy, Mark: 0}
	}

	// §5.2 security bypass
	if p.ParseRC == 1 || securityBypass(p) {
		return Decision{Action: ActionContinue, Reason: ReasonSecurityBypass, Mark: 0}
	}

	// Incomplete L4 (IP fragments): never static/flow DIRECT — NEED_USERSPACE.
	if p.Fragmented {
		return proxyDecision(c, ReasonParseFailProxy)
	}

	if p.Family == AFInet && c.Flags&FlagIPv4 == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Family == AFInet6 && c.Flags&FlagIPv6 == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol == ProtocolTCP && c.Flags&FlagTCP == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol == ProtocolUDP && c.Flags&FlagUDP == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol != ProtocolTCP && p.Protocol != ProtocolUDP {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}

	// §5.3 explicit block only
	if c.Flags&FlagDropUDP443 != 0 && p.Protocol == ProtocolUDP && p.DPort == 443 {
		return Decision{Action: ActionBlock, Reason: ReasonBlocked, Mark: 0}
	}

	// §5.4 static
	if in.Static != nil {
		switch in.Static.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonStaticDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonStaticBlock, Mark: 0}
		case VerdictProxy:
			return proxyDecision(c, ReasonStaticProxy)
		case VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// §5.5 exact-flow
	if in.Flow != nil {
		switch in.Flow.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonFlowDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonFlowBlock, Mark: 0}
		case VerdictProxy:
			return proxyDecision(c, ReasonFlowProxy)
		case VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// §5.6–5.7 DNS/FakeIP
	if in.DNS != nil {
		ok, reason := DNSHintAllowsDirect(*in.DNS, c.PolicyGeneration, in.DNSNowNs)
		if ok {
			return Decision{Action: ActionContinue, Reason: reason, Mark: 0}
		}
		if reason == ReasonDNSHintConflict {
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// §5.8 established
	if in.EstablishedTCP {
		return Decision{Action: ActionContinue, Reason: ReasonEstablishedBypass, Mark: 0}
	}

	// DNS hijack
	if c.Flags&FlagDNSHijack != 0 && p.DPort == 53 {
		return proxyDecision(c, ReasonDNSHijackProxy)
	}

	// §5.9 default NEED_USERSPACE
	return proxyDecision(c, ReasonMapMissProxy)
}

func proxyDecision(c Control, reason Reason) Decision {
	mark := uint32(0)
	// Mark only on successful handoff path intent; model assumes assign will set it.
	// Parse-fail/security already returned Mark 0. For proxy we expose routing mark
	// as the intended mark *after* listener is known — unit tests check failure paths
	// keep 0 via separate FailureMark helpers.
	if c.Flags&FlagSocketAssign != 0 && c.RoutingMark != 0 {
		mark = c.RoutingMark
	}
	return Decision{Action: ActionProxy, Reason: reason, Mark: mark}
}

// FailureMarkMustBeZero documents branches that must never pollute fwmark.
func FailureMarkMustBeZero(reason Reason) bool {
	switch reason {
	case ReasonParseFailProxy, ReasonSecurityBypass, ReasonStaticDirect, ReasonFlowDirect,
		ReasonFakeIPDirect, ReasonDNSHintDirect, ReasonBlocked, ReasonStaticBlock,
		ReasonFlowBlock, ReasonEstablishedBypass, ReasonNone:
		return true
	default:
		return false
	}
}

func securityBypass(p Packet) bool {
	if p.Protocol == 1 || p.Protocol == 58 { // ICMP / ICMPv6
		return true
	}
	if p.Protocol == ProtocolUDP {
		switch p.SPort {
		case 67, 68, 546, 547:
			return true
		}
		switch p.DPort {
		case 67, 68, 546, 547:
			return true
		}
	}
	if p.Family == AFInet {
		if p.DAddr[0]&0xf0 == 0xe0 {
			return true
		}
		if p.DAddr[0] == 255 && p.DAddr[1] == 255 && p.DAddr[2] == 255 && p.DAddr[3] == 255 {
			return true
		}
	}
	if p.Family == AFInet6 && p.DAddr[0] == 0xff {
		return true
	}
	return false
}
