# xdp-guard-rs

Small XDP firewall controlled by a Rust HTTP service.

The userspace process loads `src/fw.bpf.c`, attaches it to an interface, accepts TOML rules over HTTP, and exposes Prometheus metrics. Rules are stored in BPF maps and evaluated in priority order in the XDP path.

## Status

This is an experimental firewall/prototype. Test rules on a disposable interface or host first, especially when using `default = "block"`.

## Requirements

- Linux with XDP/eBPF support
- root or equivalent capability to load and attach BPF programs
- Rust toolchain
- `clang` with BPF target, `libbpf`, kernel headers, `bpftool`, `pkg-config`

A Nix dev shell is provided:

```sh
nix develop
```

## Run

```sh
cargo run -- <ifname>
```

The service listens on `0.0.0.0:8989`.

Load a ruleset:

```sh
curl -X POST --data-binary @example_cfg/block_udp_12345.toml \
  http://127.0.0.1:8989/update_rule_toml
```

Read metrics:

```sh
curl http://127.0.0.1:8989/metrics
```

## Rules

Rules are TOML. The top-level `default` action is used when no rule matches.

```toml
default = "allow"

[[rules]]
action = "block"
priority = 10
protocol = "udp"

[rules.dst_port]
port_begin = 12345
port_end = 12345
```

Supported match fields:

- `src_ip` / `dst_ip`: `ip4`, `mask4`
- `src_port` / `dst_port`: `port_begin`, `port_end`
- `protocol`: `any`, `icmp`, `igmp`, `tcp`, `udp`, `encap`, `ospf`, `sctp`
- `token_bucket`: `rate_per_sec`, `burst`, `count_mode = "packet" | "bytes"`

Notes:

- Port matches require `protocol = "tcp"` or `protocol = "udp"`.
- Empty rules are rejected.
- Higher `priority` rules are evaluated first.
- A token bucket only matches while it has enough tokens; when empty, evaluation continues to the next rule and `xdp_guard_rate_limit_hits_total` is incremented.

## Metrics

The service exposes Prometheus text metrics at `/metrics`:

- `xdp_guard_accepted_packets_total`
- `xdp_guard_dropped_packets_total`
- `xdp_guard_rate_limit_hits_total`
- `xdp_guard_rule_matches_total{rule="N"}`
- process metrics from the Rust service

## License

This repository uses file-level SPDX license identifiers:

- Rust userspace code, build scripts, and shared ABI declarations: MIT
- `src/fw.bpf.c`: GPL-2.0-only

See `LICENSE.md` and `LICENSES/`.
