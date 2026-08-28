#ifndef SMART_ENGINE_H
#define SMART_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct smart_engine smart_engine;

/* Increment only when field order or enum semantics change. */
#define SMART_ENGINE_ABI_VERSION 1u
#define SMART_ENGINE_MAX_CANDIDATES 8192u
#define ADAPTIVE_ENGINE_ABI_VERSION 2u

typedef struct {
    uint64_t id;
    double reliability;
    double connect_ms;
    double first_byte_ms;
    double jitter_ms;
    double throughput_bps;
    double samples;
    double weight;
    uint8_t state; /* 0 unknown, 1 healthy, 2 warming, 3 suspect, 4 open */
    uint8_t eligible; /* non-zero means the host permits selection */
} smart_candidate;

typedef struct {
    double exploration; /* non-negative score penalty */
    double switch_margin; /* relative improvement in [0, 0.95] */
    uint32_t switch_confirm_samples; /* zero is normalized to one */
    uint64_t switch_confirm_ms; /* monotonic milliseconds */
    uint64_t switch_cooldown_ms; /* monotonic milliseconds */
} smart_engine_config;

typedef struct {
    uint64_t selected_id;
    double score;
    uint8_t switched;
    uint8_t reason; /* 0 best, 1 retained, 2 confirmed, 3 no candidate */
} smart_decision;

smart_engine *smart_engine_create(smart_engine_config config);
uint32_t smart_engine_abi_version(void);
void smart_engine_destroy(smart_engine *engine);
void smart_engine_observe(smart_engine *engine, uint64_t id, uint8_t success, double elapsed_ms, uint64_t now_ms);
smart_decision smart_engine_choose(smart_engine *engine, const smart_candidate *candidates, uintptr_t count, uint64_t now_ms);
/* profile: 0 interactive, 1 bulk, 2 UDP; unknown values use interactive. */
smart_decision smart_engine_choose_profile(smart_engine *engine, const smart_candidate *candidates, uintptr_t count, uint64_t now_ms, uint8_t profile);
void smart_engine_reset(smart_engine *engine);

/* Host-neutral AdaptivePool decision kernel.  The host still owns health
 * evidence, Provider refresh, dialing, leases and persistence; this ABI owns
 * candidate ordering and sticky/failover state only. */
typedef struct adaptive_engine adaptive_engine;
typedef struct {
    uint64_t id;
    uint64_t sort_key_hi;
    uint64_t sort_key_lo;
    int32_t health_priority;
    double weighted_delay_ms;
    double throughput_bps;
    double throughput_samples;
    uint8_t supported;
    uint8_t eligible;
    uint8_t pinned;
    uint8_t leased;
} adaptive_candidate;

typedef struct {
    double switch_margin;
    uint64_t switch_cooldown_ms;
    uint8_t mode;
    uint8_t manual_failure;
} adaptive_engine_config;

typedef struct {
    uint64_t selected_id;
    uint8_t switched;
    uint8_t reason;
    double score;
} adaptive_decision;

uint32_t adaptive_engine_abi_version(void);
adaptive_engine *adaptive_engine_create(adaptive_engine_config config);
void adaptive_engine_configure(adaptive_engine *engine, adaptive_engine_config config);
void adaptive_engine_destroy(adaptive_engine *engine);
adaptive_decision adaptive_engine_choose(adaptive_engine *engine, const adaptive_candidate *candidates, uintptr_t count, uint64_t now_ms);
void adaptive_engine_set_bulk_sequence(adaptive_engine *engine, uint64_t sequence);
void adaptive_engine_remember(adaptive_engine *engine, uint64_t id, uint64_t now_ms, uint64_t cooldown_ms);
void adaptive_engine_forget(adaptive_engine *engine);
void adaptive_engine_reset(adaptive_engine *engine);

#ifdef __cplusplus
}
#endif

#endif
