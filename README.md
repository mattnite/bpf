# bpf: a Zig BPF library

This library aims to provide similar functionality as libbpf but leveraging the
zig programming language. Probes writen in either library should be able to be
loaded by the other.

# Roadmap

stdlib work:
- document all map types
- document all cmd types
- document all program and attach types
- zigify cmds
	- determine all possible errnos
- zigify bpf helpers (include documentation)
- get layout for members of structs found in bpf helpers

this lib work:
- determine how section naming translates into program types and events
- typify section naming
- figure out btf and map relocations
- typify maps
- @Type(.Struct) object
