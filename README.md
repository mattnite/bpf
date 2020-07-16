# bpf: a Zig BPF library

This library aims to provide similar functionality as libbpf but leveraging the
zig programming language. Probes writen in either library should be able to be
loaded by the other.

# Roadmap

- zigify userspace API
- zigify bpf helpers
- determine how section naming translates into program types and events
- get layout for members of structs found in bpf helpers
- get list of structs passed as contexts depending on the program type
- typify section naming
- figure out btf and map relocations
- perf buffer and ring buffer APIs
- typify maps
