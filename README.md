# wasm-bpf-guest-sdk-rust
Guest SDK of wasm-bpf, for Rust programs

It contains a crate which provided binding to the wasm-bpf APIs.

## File-descriptor attach

`wasm_attach_bpf_program_fd(object, program_name, target_fd)` attaches a
program from the object handle returned by `wasm_load_bpf_object`.
`program_name` is the guest-memory address of the NUL-terminated program name.
`target_fd` is a guest file descriptor for a directory preopened by the
runtime; a negative value asks the runtime to derive the hook from the program
section. The function returns `0` on success or a runtime-specific negative
value on failure.

Rust's linker omits this host import when a guest does not call the function,
so rebuilding an existing guest with this SDK does not by itself raise its
minimum wasm-bpf runtime version. Guests that call it require a runtime that
provides `wasm_bpf.wasm_attach_bpf_program_fd` (wasm-bpf #160/#163).
