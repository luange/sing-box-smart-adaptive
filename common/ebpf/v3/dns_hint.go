package v3

// DNSHintTable is the userspace model of v3_dns_ip_hint conflict isolation.
type DNSHintTable struct {
	entries map[DNSIPKey]DNSIPValue
}

func NewDNSHintTable() *DNSHintTable {
	return &DNSHintTable{entries: make(map[DNSIPKey]DNSIPValue)}
}

// Observe records a DNS/FakeIP association. Conflicts force MUST_CONTROL semantics
// (proxy_refs and direct_refs both non-zero → kernel denies DIRECT).
func (t *DNSHintTable) Observe(key DNSIPKey, direct bool, evidence uint8, policyID, generation uint32, expiresNs, nowNs uint64) DNSIPValue {
	if t.entries == nil {
		t.entries = make(map[DNSIPKey]DNSIPValue)
	}
	cur, ok := t.entries[key]
	if !ok || cur.Generation != generation {
		cur = DNSIPValue{
			PolicyID:   policyID,
			Generation: generation,
			Evidence:   evidence,
		}
	}
	if direct {
		cur.DirectRefs++
	} else {
		cur.ProxyRefs++
	}
	// Evidence can only strengthen within the same generation when no conflict.
	if evidenceRank(evidence) > evidenceRank(cur.Evidence) && cur.ProxyRefs == 0 {
		cur.Evidence = evidence
	}
	if cur.ProxyRefs > 0 && cur.DirectRefs > 0 {
		// Conflict: keep counts, force weak so kernel path never DIRECT.
		cur.Evidence = DNSEvidenceWeak
	}
	cur.ExpiresNs = expiresNs
	cur.LastSeenNs = nowNs
	cur.PolicyID = policyID
	cur.Generation = generation
	t.entries[key] = cur
	return cur
}

func evidenceRank(e uint8) int {
	switch e {
	case DNSEvidenceFakeIP:
		return 3
	case DNSEvidenceStrong:
		return 2
	case DNSEvidenceWeak:
		return 1
	default:
		return 0
	}
}

// Lookup returns a copy if present.
func (t *DNSHintTable) Lookup(key DNSIPKey) (DNSIPValue, bool) {
	if t == nil || t.entries == nil {
		return DNSIPValue{}, false
	}
	v, ok := t.entries[key]
	return v, ok
}

// InvalidateGeneration drops entries not matching generation (optional eager GC).
func (t *DNSHintTable) InvalidateGeneration(generation uint32) {
	if t == nil || t.entries == nil {
		return
	}
	for k, v := range t.entries {
		if v.Generation != generation {
			delete(t.entries, k)
		}
	}
}
