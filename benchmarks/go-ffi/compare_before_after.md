# Go FFI benchmark comparison (before vs after callback)

Environment:
- parse iterations: 200,000
- verify iterations: 1,000
- command: `scripts/benchmark_go_ffi.sh <label> 200000 1000`

| Mode | Metric | Before | After | Delta | Delta % |
|---|---:|---:|---:|---:|---:|
| parse | duration_ms | 39094 | 38408 | -686 | -1.75% |
| parse | rss_delta_kb | 8416 | 8320 | -96 | -1.14% |
| verify | duration_ms | 971 | 920 | -51 | -5.25% |
| verify | rss_delta_kb | 6592 | 6816 | +224 | +3.40% |

Raw files:
- `benchmarks/go-ffi/before-callback_parse.json`
- `benchmarks/go-ffi/before-callback_verify.json`
- `benchmarks/go-ffi/after-callback_parse.json`
- `benchmarks/go-ffi/after-callback_verify.json`
