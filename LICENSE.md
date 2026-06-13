# License

This repository uses file-level SPDX license identifiers.

- Rust userspace code, build scripts, and shared ABI declarations are licensed under the MIT License. See `LICENSES/MIT.txt`.
- The eBPF/XDP program in `src/fw.bpf.c` is licensed under GPL-2.0-only. See `LICENSES/GPL-2.0-only.txt`.

The `char LICENSE[] SEC("license") = "GPL";` declaration in `src/fw.bpf.c` is required BPF object metadata for the Linux kernel/libbpf loader. It does not replace the source-level SPDX notice above the file.
