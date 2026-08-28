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

#ifdef __cplusplus
}
#endif

#endif
