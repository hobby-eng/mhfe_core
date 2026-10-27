/*
 * The stack check of the Argon2 engine's C code on Linux. `cargo xtask argon2-stack` links it
 * twice against the engine's library as Cargo builds it, and runs both.
 *
 * Each thread of one call runs on a stack of this program, painted with a pattern first: the
 * thread that makes the call, and the lane threads the vendored code starts, through the
 * pthread_create() below, which the vendored code calls instead of the C library's. When a
 * thread's work is done, the thread reads its stack below its current frame: the calling thread
 * after the call returns, a lane thread in the pthread_exit() below, which the vendored code calls
 * once the thread's segment is filled. A byte that is not the pattern was written by the call.
 *
 * - As shipped, the call is mhfe_argon2_ctx(), whose wrapper clears the stack: every byte the call
 *   wrote must be zero again.
 * - Built with MHFE_STACK_MEASURE, the call is the vendored argon2_ctx() with a fill_segment()
 *   that does not clear: the deepest byte it writes on each thread is printed, and it must lie
 *   less than MHFE_STACK_CLEAR_BYTES below the frame that reads the stack, which is about where
 *   the frame of the wrapper's clear begins.
 *
 * The few hundred bytes just below the reading frame are left out: the reading frame itself and
 * the frames of the calls that ended the thread's work lie there, written after the clear.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2_wrap.h"
#include "core.h"

/* The stack of each thread: far more than the call needs. */
#define STACK_BYTES (256 * 1024)
#define STACK_ALIGNMENT 4096
/* The pattern every stack is painted with before its thread starts. */
#define PAINT 0xa5
/* What lies just below the reading frame, left out (see above). */
#define FRAME_SLACK 256
/* One call starts 16 lane threads at one pass and four lanes, beside the calling thread. */
#define MOST_THREADS 64

/* The painted stack of one thread and what its reading found. */
struct painted_stack {
    unsigned char *low;
    void *(*start)(void *);
    void *argument;
    /* How far below the reading frame the deepest byte written lies. */
    size_t deepest;
    /* The bytes written that are not zero. */
    size_t left;
};

static struct painted_stack stacks[MOST_THREADS];
/*
 * Threads start one after another, from main() and then from the calling thread, so the count
 * needs no lock.
 */
static size_t started;
static _Thread_local struct painted_stack *own_stack;

static int (*libc_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *),
                                  void *);
static void (*libc_pthread_exit)(void *);

/* Reads the thread's own stack below this frame. Not inlined, so that it has a frame of its own. */
static __attribute__((noinline)) void read_own_stack(void) {
    volatile unsigned char here = 0;
    uintptr_t frame = (uintptr_t)&here;
    const volatile unsigned char *byte;
    for (byte = own_stack->low; (uintptr_t)byte < frame - FRAME_SLACK; byte++) {
        if (*byte == PAINT) {
            continue;
        }
        if (own_stack->deepest == 0) {
            own_stack->deepest = frame - (uintptr_t)byte;
        }
        if (*byte != 0) {
            own_stack->left++;
        }
    }
}

static void *start_on_painted_stack(void *stack) {
    own_stack = stack;
    return own_stack->start(own_stack->argument);
}

int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attributes,
                   void *(*start)(void *), void *restrict argument) {
    /* The vendored code passes no attributes, and neither does main(). */
    (void)attributes;
    if (started == MOST_THREADS) {
        return EAGAIN;
    }
    struct painted_stack *stack = &stacks[started];
    stack->low = aligned_alloc(STACK_ALIGNMENT, STACK_BYTES);
    if (stack->low == NULL) {
        return ENOMEM;
    }
    started++;
    memset(stack->low, PAINT, STACK_BYTES);
    stack->start = start;
    stack->argument = argument;
    pthread_attr_t on_stack;
    int result = pthread_attr_init(&on_stack);
    if (result == 0) {
        result = pthread_attr_setstack(&on_stack, stack->low, STACK_BYTES);
    }
    if (result == 0) {
        result = libc_pthread_create(thread, &on_stack, start_on_painted_stack, stack);
    }
    pthread_attr_destroy(&on_stack);
    return result;
}

void pthread_exit(void *value) {
    read_own_stack();
    libc_pthread_exit(value);
    abort();
}

#ifdef MHFE_STACK_MEASURE
/* The renamed copies of the vendored fill_segment(), as argon2_wrap.c declares them. */
#if defined(__x86_64__)
void mhfe_fill_segment_sse2(const argon2_instance_t *instance, argon2_position_t position);
void mhfe_fill_segment_ssse3(const argon2_instance_t *instance, argon2_position_t position);
#else
void mhfe_fill_segment_ref(const argon2_instance_t *instance, argon2_position_t position);
#endif

/*
 * A deliberate copy of the fill_segment() of argon2_wrap.c without its clear of the stack, so
 * that the stack shows what the vendored code writes.
 */
void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
#if defined(__x86_64__)
    if (instance->context_ptr->flags & MHFE_FLAG_SSSE3) {
        mhfe_fill_segment_ssse3(instance, position);
    } else {
        mhfe_fill_segment_sse2(instance, position);
    }
#else
    mhfe_fill_segment_ref(instance, position);
#endif
}
#endif

/* Public test inputs, outside every stack: one pass at a small memory, MHFE's four lanes. */
static uint8_t password[] = "public test password";
static uint8_t salt[] = "0123456789abcdef";
static uint8_t tag[32];
static argon2_context context;
static int call_result;

static __attribute__((noinline)) int call_argon2(uint32_t flags) {
    context = (argon2_context){
        .out = tag,
        .outlen = sizeof tag,
        .pwd = password,
        .pwdlen = sizeof password - 1,
        .salt = salt,
        .saltlen = sizeof salt - 1,
        .t_cost = 1,
        .m_cost = 64,
        .lanes = 4,
        .threads = 4,
        .version = ARGON2_VERSION_13,
        .flags = flags,
    };
#ifdef MHFE_STACK_MEASURE
    return argon2_ctx(&context, Argon2_id);
#else
    return mhfe_argon2_ctx(&context, Argon2_id);
#endif
}

static void *calling_thread(void *flags) {
    call_result = call_argon2(*(const uint32_t *)flags);
    read_own_stack();
    return NULL;
}

/* One call on the copy of the Argon2 core that `flags` selects; 1 when the check fails. */
static int check(const char *copy, uint32_t flags) {
    pthread_t caller;
    started = 0;
    if (pthread_create(&caller, NULL, calling_thread, &flags) != 0 ||
        pthread_join(caller, NULL) != 0 || call_result != ARGON2_OK) {
        fprintf(stderr, "%s copy: the call failed (%d)\n", copy, call_result);
        return 1;
    }
    size_t deepest = 0;
    size_t left = 0;
    for (size_t index = 0; index < started; index++) {
        if (stacks[index].deepest > deepest) {
            deepest = stacks[index].deepest;
        }
        left += stacks[index].left;
        free(stacks[index].low);
    }
    memset(stacks, 0, sizeof stacks);
    /* The lane threads must have run on painted stacks too. */
    int failed = started < 2;
#ifdef MHFE_STACK_MEASURE
    printf("%s copy without the clears: the vendored code writes %zu bytes deep on %zu thread "
           "stacks and leaves %zu bytes that are not zero; MHFE_STACK_CLEAR_BYTES is %d\n",
           copy, deepest, started, left, MHFE_STACK_CLEAR_BYTES);
    failed |= deepest >= MHFE_STACK_CLEAR_BYTES;
#else
    printf("%s copy as shipped: the call and its clears write %zu bytes deep on %zu thread stacks "
           "and leave %zu bytes that are not zero\n",
           copy, deepest, started, left);
    failed |= left != 0;
#endif
    return failed;
}

int main(void) {
    libc_pthread_create = (int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *),
                                   void *))dlsym(RTLD_NEXT, "pthread_create");
    libc_pthread_exit = (void (*)(void *))dlsym(RTLD_NEXT, "pthread_exit");
    if (libc_pthread_create == NULL || libc_pthread_exit == NULL) {
        fprintf(stderr, "the C library's thread functions were not found\n");
        return 1;
    }
    int failed = 0;
#if defined(__x86_64__)
    failed |= check("SSE2", 0);
    if (__builtin_cpu_supports("ssse3")) {
        failed |= check("SSSE3", MHFE_FLAG_SSSE3);
    }
#else
    failed |= check("portable", 0);
#endif
    return failed;
}
