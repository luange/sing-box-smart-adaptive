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
