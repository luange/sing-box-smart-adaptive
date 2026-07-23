def is_parallel_shadow:
  .type == "adaptive_pool"
  and .shadow == true
  and (.tag | endswith("-ADAPTIVE-SHADOW"));

if ([.outbounds[] | select(.type == "smart")]|length) != 5 then
  error("expected five legacy Smart groups")
elif ([.outbounds[] | select(is_parallel_shadow)]|length) != 5 then
  error("expected five parallel AdaptivePool shadow groups")
else
  .outbounds |= [
    .[]
    | if .type == "smart" then empty
      elif is_parallel_shadow then
        .tag |= sub("-ADAPTIVE-SHADOW$"; "")
        | .shadow = false
      else .
      end
  ]
end
