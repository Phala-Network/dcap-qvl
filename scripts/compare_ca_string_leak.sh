#!/usr/bin/env bash
set -euo pipefail

# Compare memory growth between:
# 1) leaky mode: Box::leak(ca.to_string().into_boxed_str())
# 2) fixed mode: borrowing &str
#
# This isolates the exact conversion pattern discussed in src/ffi.rs and
# prints RSS deltas so the leak behavior is observable locally.
#
# Usage:
#   ./scripts/compare_ca_string_leak.sh [iterations] [sample_every]
#
# Example:
#   ./scripts/compare_ca_string_leak.sh 2000000 100000

ITERATIONS="${1:-2000000}"
SAMPLE_EVERY="${2:-100000}"

if ! command -v rustc >/dev/null 2>&1; then
  echo "error: rustc not found"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/probe.rs" <<'RS'
use std::env;
use std::process::Command;

fn rss_kb() -> u64 {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .expect("ps command failed");
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse::<u64>().unwrap_or(0)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: probe <leak|fixed> <iterations> <sample_every>");
        std::process::exit(2);
    }

    let mode = &args[1];
    let iterations: usize = args[2].parse().expect("bad iterations");
    let sample_every: usize = args[3].parse().expect("bad sample_every");
    let ca = "processor";

    println!("mode={mode}");
    println!("iter,rss_kb");
    println!("0,{}", rss_kb());

    for i in 1..=iterations {
        if mode == "leak" {
            let leaked: &'static str = Box::leak(ca.to_string().into_boxed_str());
            std::hint::black_box(leaked);
        } else if mode == "fixed" {
            let borrowed: &str = ca;
            std::hint::black_box(borrowed);
        } else {
            eprintln!("unknown mode: {mode}");
            std::process::exit(2);
        }

        if i % sample_every == 0 || i == iterations {
            println!("{i},{}", rss_kb());
        }
    }
}
RS

rustc -O "$TMP_DIR/probe.rs" -o "$TMP_DIR/probe"

run_mode() {
  local mode="$1"
  local out="$TMP_DIR/${mode}.csv"
  "$TMP_DIR/probe" "$mode" "$ITERATIONS" "$SAMPLE_EVERY" | tee "$out" >/dev/null

  local start end delta
  start="$(awk -F',' '/^[0-9]+,[0-9]+$/ {print $2; exit}' "$out")"
  end="$(awk -F',' '/^[0-9]+,[0-9]+$/ {v=$2} END {print v}' "$out")"
  delta="$((end - start))"
  echo "$mode,$start,$end,$delta"
}

echo "running: iterations=$ITERATIONS sample_every=$SAMPLE_EVERY"
echo "mode,start_rss_kb,end_rss_kb,delta_rss_kb"
run_mode leak
run_mode fixed

