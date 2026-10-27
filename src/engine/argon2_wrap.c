/*
 * MHFE's wrapper around the vendored reference Argon2 code; argon2_wrap.h says what it does.
 */

#include "argon2_wrap.h"

#include <stddef.h>

#include "core.h"

#if defined(_MSC_VER)
#include <intrin.h>
#define MHFE_NOINLINE __declspec(noinline)
#else
#define MHFE_NOINLINE __attribute__((noinline))
#endif

const uint32_t mhfe_flag_ssse3 = MHFE_FLAG_SSSE3;

/*
 * The vendored fill_segment() of each compiled copy of the Argon2 core, renamed as
 * argon2-sources.txt states: on x86-64 opt.c twice, with SSE2, which every 64-bit x86 processor
 * has, and with SSSE3, 7 to 10% faster; elsewhere ref.c.
 */
#if defined(__x86_64__) || defined(_M_X64)
void mhfe_fill_segment_sse2(const argon2_instance_t *instance, argon2_position_t position);
void mhfe_fill_segment_ssse3(const argon2_instance_t *instance, argon2_position_t position);
#else
void mhfe_fill_segment_ref(const argon2_instance_t *instance, argon2_position_t position);
#endif

/*
 * Not inlined, so that its array lies below the caller's frame, where the frames of the calls the
 * caller made before lay. Volatile stores, and a barrier the compiler cannot see through, keep the
 * writes, although nothing reads the array again.
 */
MHFE_NOINLINE void mhfe_clear_stack(void) {
    volatile uint8_t stack[MHFE_STACK_CLEAR_BYTES];
    size_t at;
    for (at = 0; at < sizeof stack; at++) {
        stack[at] = 0;
    }
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" : : "r"(stack) : "memory");
#endif
}

/*
 * The fill_segment() that core.c calls, on the calling thread when a call has one thread and on
 * each lane's own thread otherwise: the chosen copy fills one segment, then the stack it used is
 * cleared, so that a lane thread leaves nothing when it exits and its stack goes back to the C
 * library's cache.
 * The choice travels in the context of the call: src/engine/ffi.rs sets MHFE_FLAG_SSSE3 when the
 * processor has SSSE3, so two calls never share any state.
 */
void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
#if defined(__x86_64__) || defined(_M_X64)
    if (instance->context_ptr->flags & MHFE_FLAG_SSSE3) {
        mhfe_fill_segment_ssse3(instance, position);
    } else {
        mhfe_fill_segment_sse2(instance, position);
    }
#else
    mhfe_fill_segment_ref(instance, position);
#endif
    mhfe_clear_stack();
}

int mhfe_argon2_ctx(argon2_context *context, argon2_type type) {
    int result = argon2_ctx(context, type);
    mhfe_clear_stack();
    return result;
}
