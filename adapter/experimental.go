package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/varbin"
)

type ClashServer interface {
	LifecycleService
	Mode() string
	ModeList() []string
	SetMode(mode string)
	AddModeUpdateHook(hook *observable.Subscriber[struct{}])
}

type URLTestHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type V2RayServer interface {
	LifecycleService
	StatsService() ConnectionTracker
}

type CacheFile interface {
	LifecycleService

	CacheID() string

	StoreFakeIP() bool
	FakeIPStorage

	StoreRDRC() bool
	RDRCStore

	StoreDNS() bool
	DNSCacheStore

	SetDisableExpire(disableExpire bool)
	SetOptimisticTimeout(timeout time.Duration)

	LoadMode() string
	StoreMode(mode string) error
	LoadSelected(group string) string
	StoreSelected(group string, selected string) error
	LoadGroupExpand(group string) (isExpand bool, loaded bool)
	StoreGroupExpand(group string, expand bool) error
	LoadRuleSet(tag string) *SavedBinary
	SaveRuleSet(tag string, set *SavedBinary) error
	LoadExternalUI(tag string) *SavedBinary
	SaveExternalUI(tag string, info *SavedBinary) error
	LoadSubscription(tag string) *SavedBinary
	SaveSubscription(tag string, sub *SavedBinary) error
}

type SavedBinary struct {
	Hash        hash.HashType
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(1))
	if err != nil {
		return nil, err
	}
	hash, err := s.Hash.MarshalBinary()
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(hash)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(hash)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.Content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.Content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.LastEtag)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(s.LastEtag)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	hashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	hash := make([]byte, hashLength)
	_, err = io.ReadFull(reader, hash)
	if err != nil {
		return err
	}
	err = s.Hash.UnmarshalBinary(hash)
	if err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	s.Content = make([]byte, contentLength)
	_, err = io.ReadFull(reader, s.Content)
	if err != nil {
		return err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	etagBytes := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etagBytes)
	if err != nil {
		return err
	}
	s.LastEtag = string(etagBytes)
	return nil
}

type OutboundGroup interface {
	Outbound
	Now() string
	All() []string
}

type PreMatchOutboundGroup interface {
	OutboundGroup
	// selectOutbound resolves nested groups and returns nil when the selected outbound is not eligible for pre-match.
	// Implementations must not advance consumptive selection state when selectOutbound returns nil, but may retain
	// a stable mapping when it is required for the following L4 selection to replay the same outbound.
	SelectPreMatchOutbound(metadata *InboundContext, selectOutbound func(Outbound) (Outbound, PreMatchAction)) (Outbound, PreMatchAction)
}

// PreMatchDisabledOutbound keeps transparent flows on the L4 outbound path.
// Groups use it when resolving to a leaf would bypass retry or observation.
type PreMatchDisabledOutbound interface {
	DisablePreMatch()
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

type LoadBalanceGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

type SelectorGroup interface {
	Selected() Outbound
}

type SmartCandidateStatus struct {
	Tag           string  `json:"tag"`
	State         string  `json:"state"`
	Score         float64 `json:"score"`
	Weight        float64 `json:"weight,omitempty"`
	WeightRule    string  `json:"weight_rule,omitempty"`
	WeightExact   bool    `json:"weight_rule_exact,omitempty"`
	Reliability   float64 `json:"reliability"`
	ConnectMS     float64 `json:"connect_ms,omitempty"`
	FirstByteMS   float64 `json:"first_byte_ms,omitempty"`
	ThroughputBPS float64 `json:"throughput_bps,omitempty"`
	Samples       float64 `json:"samples"`
	Reason        string  `json:"reason,omitempty"`
}

type SmartGroupStatus struct {
	Selected                  string                 `json:"selected,omitempty"`
	Pinned                    string                 `json:"pinned,omitempty"`
	Network                   string                 `json:"network,omitempty"`
	Site                      string                 `json:"site,omitempty"`
	Reason                    string                 `json:"reason,omitempty"`
	UpdatedAt                 time.Time              `json:"updated_at,omitempty"`
	CandidateCount            int                    `json:"candidate_count"`
	CandidateDetailsCount     int                    `json:"candidate_details_count"`
	CandidateDetailsTruncated bool                   `json:"candidate_details_truncated"`
	StateCounts               map[string]int         `json:"state_counts"`
	TemporaryOverride         string                 `json:"temporary_override,omitempty"`
	OverrideExpiresAt         *time.Time             `json:"override_expires_at,omitempty"`
	OverrideRemainingSeconds  int64                  `json:"override_remaining_seconds,omitempty"`
	OverrideReason            string                 `json:"override_reason,omitempty"`
	ReachTests                []SmartReachTestStatus `json:"reach_tests,omitempty"`
	Candidates                []SmartCandidateStatus `json:"candidates"`
}

type SmartReachCandidateStatus struct {
	Tag        string    `json:"tag"`
	State      string    `json:"state"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
}

type SmartReachTestStatus struct {
	Tag                       string                      `json:"tag"`
	Preset                    string                      `json:"preset,omitempty"`
	Domains                   []string                    `json:"domains"`
	URL                       string                      `json:"url"`
	CheckedAt                 time.Time                   `json:"checked_at,omitempty"`
	StateCounts               map[string]int              `json:"state_counts"`
	CandidateCount            int                         `json:"candidate_count"`
	CandidateDetailsCount     int                         `json:"candidate_details_count"`
	CandidateDetailsTruncated bool                        `json:"candidate_details_truncated"`
	Candidates                []SmartReachCandidateStatus `json:"candidates"`
}

type SmartGroup interface {
	URLTestGroup
	SmartStatus() SmartGroupStatus
	SelectOutbound(tag string) bool
	ClearSelection()
	SelectTemporaryOutbound(tag string, ttl time.Duration, reason string) bool
	ClearTemporarySelection()
}

func OutboundTag(detour Outbound) string {
	if group, isGroup := detour.(OutboundGroup); isGroup {
		if now := group.Now(); now != "" {
			return now
		}
	}
	return detour.Tag()
}
