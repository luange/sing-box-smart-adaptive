def adaptive_shadow:
  . as $smart
  | {
      type: "adaptive_pool",
      tag: ($smart.tag + "-ADAPTIVE-SHADOW"),
      outbounds: ($smart.outbounds // []),
      providers: ($smart.providers // []),
      use_all_providers: ($smart.use_all_providers // false),
      shadow: true,
      probe: {
        url: "https://www.gstatic.com/generate_204",
        coverage_interval: ($smart.probe_interval // "10m"),
        timeout: ($smart.probe_timeout // "5s"),
        concurrency: 8,
        queue_size: 4096
      },
      policy: {
        default: "adaptive",
        adaptive_lease_ttl: ($smart.site_stickiness // "10m"),
        max_attempts: ($smart.max_attempts // 3),
        attempt_timeout: ($smart.attempt_timeout // "4s"),
        hedge_delay: "450ms",
        manual_failure: "fallback"
      },
      state: {
        path: ("/var/lib/singbox-adaptive-vm107/" + $smart.tag),
        retention: ($smart.history_retention // "168h"),
        max_entries: 4096
      }
    }
  | if $smart.include != null then .include = $smart.include else . end
  | if $smart.exclude != null then .exclude = $smart.exclude else . end;

. as $config
| if any($config.outbounds[]; .type == "adaptive_pool" and (.tag | endswith("-ADAPTIVE-SHADOW")))
  then error("parallel AdaptivePool shadow groups already exist")
  else .outbounds += [$config.outbounds[] | select(.type == "smart") | adaptive_shadow]
  end
