/*
 * MHFE's own C code around the vendored reference Argon2 implementation, which stays unchanged.
 * Rust calls mhfe_argon2_ctx(), never argon2_ctx(), and the vendored core.c calls the
 * fill_segment() of argon2_wrap.c, which runs a renamed copy of the vendored one. Both then clear
 * the stack the vendored code used: it holds values derived from the password, such as H0, the
 * BLAKE2b state of initial_hash() and the blocks a segment computes on the stack.
 */
#ifndef MHFE_ARGON2_WRAP_H
#define MHFE_ARGON2_WRAP_H

#include <stdint.h>

#include "argon2.h"

/*
 * MHFE's bit in argon2_context.flags: run the copy of opt.c compiled with SSSE3 instead of the
 * SSE2 one, on x86-64. Bit 31, far from the two lowest bits, ARGON2_FLAG_CLEAR_PASSWORD and
 * ARGON2_FLAG_CLEAR_SECRET, which are all the vendored code reads; it passes the context through
 * unchanged.
 */
#define MHFE_FLAG_SSSE3 UINT32_C(0x80000000)

/*
 * The stack below its caller's frame that mhfe_clear_stack() overwrites: more than the deepest
 * the vendored code writes in one call or one segment, with a margin. `cargo xtask argon2-stack`
 * measures that depth, about 6 KiB on x86-64, and fails when it reaches this size.
 */
#define MHFE_STACK_CLEAR_BYTES (16 * 1024)

/* MHFE_FLAG_SSSE3, for the Rust binding, which reads it here rather than keep a copy. */
extern const uint32_t mhfe_flag_ssse3;

/* Overwrites MHFE_STACK_CLEAR_BYTES of the stack below the caller's frame with zeros. */
void mhfe_clear_stack(void);

/* argon2_ctx(), then mhfe_clear_stack() on the calling thread. */
int mhfe_argon2_ctx(argon2_context *context, argon2_type type);

#endif
