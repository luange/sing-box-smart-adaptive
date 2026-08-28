package v3

import "testing"

func TestDNSHintConflictIsolation(t *testing.T) {
	tab := NewDNSHintTable()
	key := DNSIPKey{Family: AFInet, Addr: [16]byte{1, 2, 3, 4}}
	v := tab.Observe(key, true, DNSEvidenceStrong, 1, 1, 1000, 10)
	ok, reason := DNSHintAllowsDirect(v, 1, 20)
	if !ok || reason != ReasonDNSHintDirect {
		t.Fatalf("strong direct: ok=%v reason=%v", ok, reason)
	}
	// Same IP later observed for PROXY domain (CDN share).
	v = tab.Observe(key, false, DNSEvidenceStrong, 2, 1, 1000, 30)
	ok, reason = DNSHintAllowsDirect(v, 1, 40)
	if ok {
		t.Fatalf("conflict must not direct, got reason=%v value=%+v", reason, v)
	}
	if reason != ReasonDNSHintConflict {
		t.Fatalf("want conflict reason, got %v", reason)
	}
	if v.Evidence != DNSEvidenceWeak {
		t.Fatalf("evidence degraded to weak, got %d", v.Evidence)
	}
}

func TestDNSWeakNeverDirect(t *testing.T) {
	v := DNSIPValue{DirectRefs: 3, ProxyRefs: 0, Generation: 1, Evidence: DNSEvidenceWeak, ExpiresNs: 99}
	ok, _ := DNSHintAllowsDirect(v, 1, 1)
	if ok {
		t.Fatal("weak evidence must not allow direct")
	}
}

func TestDNSFakeIPAuthoritative(t *testing.T) {
	v := DNSIPValue{DirectRefs: 1, ProxyRefs: 0, Generation: 5, Evidence: DNSEvidenceFakeIP, ExpiresNs: 100}
	ok, reason := DNSHintAllowsDirect(v, 5, 50)
	if !ok || reason != ReasonFakeIPDirect {
		t.Fatalf("ok=%v reason=%v", ok, reason)
	}
	ok, _ = DNSHintAllowsDirect(v, 6, 50)
	if ok {
		t.Fatal("generation mismatch")
	}
}

func TestDNSHintTableExpiresAndBoundsEntries(t *testing.T) {
	tab := NewDNSHintTable()
	for i := 0; i < dnsHintTableLimit+1; i++ {
		key := DNSIPKey{Family: AFInet, Addr: [16]byte{byte(i >> 8), byte(i)}}
		tab.Observe(key, true, DNSEvidenceStrong, 1, 1, ^uint64(0), uint64(i))
	}
	if len(tab.entries) != dnsHintTableLimit {
		t.Fatalf("DNS hint mirror grew beyond bound: %d", len(tab.entries))
	}
	oldest := DNSIPKey{Family: AFInet, Addr: [16]byte{0, 0}}
	if _, ok := tab.Lookup(oldest); ok {
		t.Fatal("oldest DNS hint was not evicted at capacity")
	}
	// Expired entries are removed on the next observation even when the table
	// is far below its capacity.
	expiredKey := DNSIPKey{Family: AFInet, Addr: [16]byte{1, 1}}
	expired := tab.entries[expiredKey]
	expired.ExpiresNs = 1
	tab.entries[expiredKey] = expired
	tab.Observe(DNSIPKey{Family: AFInet, Addr: [16]byte{9, 9}}, true, DNSEvidenceStrong, 1, 1, 10, 2000)
	if _, ok := tab.Lookup(expiredKey); ok {
		t.Fatal("expired DNS hint was retained")
	}
}

func TestDNSHintReferenceCountersSaturate(t *testing.T) {
	tab := NewDNSHintTable()
	key := DNSIPKey{Family: AFInet, Addr: [16]byte{8, 8, 8, 8}}
	tab.entries[key] = DNSIPValue{Generation: 1, Evidence: DNSEvidenceStrong, ExpiresNs: 100, LastSeenNs: 1, DirectRefs: ^uint32(0), ProxyRefs: ^uint32(0)}
	v := tab.Observe(key, true, DNSEvidenceStrong, 1, 1, 100, 2)
	if v.DirectRefs != ^uint32(0) || v.ProxyRefs != ^uint32(0) {
		t.Fatalf("DNS hint reference counters wrapped: %+v", v)
	}
}
