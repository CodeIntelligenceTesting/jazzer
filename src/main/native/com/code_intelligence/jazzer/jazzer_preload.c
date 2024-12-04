// Copyright 2024 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * Dynamically exported definitions of fuzzer hooks and libc functions that
 * forward to the symbols provided by the jazzer_driver JNI library once it has
 * been loaded.
 */

#define _GNU_SOURCE  // for RTLD_NEXT
#include <dlfcn.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __APPLE__
// Using dyld's interpose feature requires knowing the addresses of libc
// functions.
#include <string.h>
#endif

#if defined(__APPLE__) && defined(__arm64__)
// arm64 has a fixed instruction length of 32 bits, which means that the lowest
// two bits of the return address of a function are always zero. Since
// libFuzzer's value profiling uses the lowest bits of the address to index into
// a hash table, we increase their entropy by shifting away the constant bits.
#define GET_CALLER_PC() \
  ((void *)(((uintptr_t)__builtin_return_address(0)) >> 2))
#else
#define GET_CALLER_PC() __builtin_return_address(0)
#endif
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// Unwraps (foo, bar) passed as arguments to foo, bar - this allows passing
// multiple var args into a single macro.
#define UNWRAP_VA_ARGS(...) __VA_ARGS__

// Define a dynamic, global symbol such as __sanitizer_weak_hook_memcmp that
// calls the local symbol of the same name in the jazzer_driver shared library
// loaded in the JVM.
#define DEFINE_LIBC_HOOK(name, ret, params, args)                           \
  typedef void (*name##_hook_t)(void *, UNWRAP_VA_ARGS params, ret);        \
  static _Atomic name##_hook_t name##_hook;                                 \
                                                                            \
  __attribute__((visibility("default"))) void __sanitizer_weak_hook_##name( \
      void *called_pc, UNWRAP_VA_ARGS params, ret result) {                 \
    name##_hook_t hook =                                                    \
        atomic_load_explicit(&name##_hook, memory_order_relaxed);           \
    if (LIKELY(hook != NULL)) {                                             \
      hook(called_pc, UNWRAP_VA_ARGS args, result);                         \
    }                                                                       \
  }

#define INIT_LIBC_HOOK(handle, name) \
  atomic_store(&name##_hook, dlsym(handle, "__sanitizer_weak_hook_" #name))

#ifdef __linux__
// Alternate definitions for libc functions mimicking those that libFuzzer would
// provide if it were linked into the JVM. All these functions invoke the real
// libc function loaded from the next library in search order (either libc
// itself or a sanitizer's interceptor).
//
// Function pointers have to be loaded and stored atomically even if libc
// functions are invoked from different threads, but we do not need any
// synchronization guarantees - in the worst case, we will non-deterministically
// lose a few hook invocations.

#define DEFINE_LIBC_INTERCEPTOR(name, ret, params, args)                   \
  DEFINE_LIBC_HOOK(name, ret, params, args)                                \
                                                                           \
  typedef ret (*name##_t)(UNWRAP_VA_ARGS params);                          \
  static _Atomic name##_t name##_real;                                     \
                                                                           \
  __attribute__((visibility("default"))) ret name(UNWRAP_VA_ARGS params) { \
    name##_t name##_real_local =                                           \
        atomic_load_explicit(&name##_real, memory_order_relaxed);          \
    if (UNLIKELY(name##_real_local == NULL)) {                             \
      name##_real_local = dlsym(RTLD_NEXT, #name);                         \
      atomic_store_explicit(&name##_real, name##_real_local,               \
                            memory_order_relaxed);                         \
    }                                                                      \
    ret result = name##_real_local(UNWRAP_VA_ARGS args);                   \
    __sanitizer_weak_hook_##name(GET_CALLER_PC(), UNWRAP_VA_ARGS args,     \
                                 result);                                  \
    return result;                                                         \
  }

#elif __APPLE__
// macOS namespace concept makes it impossible to override symbols in shared
// library dependencies simply by defining them. Instead, the dynamic linker's
// interpose feature is used to request that one function, identified by its
// address, is replaced by another at runtime.

typedef struct {
  const uintptr_t interceptor;
  const uintptr_t func;
} interpose_t;

#define INTERPOSE(_interceptor, _func)                        \
  __attribute__((used)) static interpose_t _interpose_##_func \
      __attribute__((section("__DATA,__interpose"))) = {      \
          (uintptr_t)&_interceptor, (uintptr_t)&_func};

#define DEFINE_LIBC_INTERCEPTOR(name, ret, params, args)               \
  DEFINE_LIBC_HOOK(name, ret, params, args)                            \
                                                                       \
  __attribute__((visibility("default")))                               \
  ret interposed_##name(UNWRAP_VA_ARGS params) {                       \
    ret result = name(UNWRAP_VA_ARGS args);                            \
    __sanitizer_weak_hook_##name(GET_CALLER_PC(), UNWRAP_VA_ARGS args, \
                                 result);                              \
    return result;                                                     \
  }                                                                    \
                                                                       \
  INTERPOSE(interposed_##name, name)
#else
// TODO: Use https://github.com/microsoft/Detours to add Windows support.
#error "jazzer_preload is not supported on this OS"
#endif

DEFINE_LIBC_INTERCEPTOR(bcmp, int, (const void *s1, const void *s2, size_t n),
                        (s1, s2, n))
DEFINE_LIBC_INTERCEPTOR(memcmp, int, (const void *s1, const void *s2, size_t n),
                        (s1, s2, n))
DEFINE_LIBC_INTERCEPTOR(strncmp, int,
                        (const char *s1, const char *s2, size_t n), (s1, s2, n))
DEFINE_LIBC_INTERCEPTOR(strncasecmp, int,
                        (const char *s1, const char *s2, size_t n), (s1, s2, n))
DEFINE_LIBC_INTERCEPTOR(strcmp, int, (const char *s1, const char *s2), (s1, s2))
DEFINE_LIBC_INTERCEPTOR(strcasecmp, int, (const char *s1, const char *s2),
                        (s1, s2))
DEFINE_LIBC_INTERCEPTOR(strstr, char *, (const char *s1, const char *s2),
                        (s1, s2))
DEFINE_LIBC_INTERCEPTOR(strcasestr, char *, (const char *s1, const char *s2),
                        (s1, s2))
DEFINE_LIBC_INTERCEPTOR(memmem, void *,
                        (const void *s1, size_t n1, const void *s2, size_t n2),
                        (s1, n1, s2, n2))

// Native libraries instrumented for fuzzing include references to fuzzer hooks
// that are resolved by the dynamic linker. We need to route these to the
// corresponding local symbols in the Jazzer driver JNI library.
// The __sanitizer_cov_trace_* family of functions is only invoked from code
// compiled with -fsanitize=fuzzer. We can assume that the Jazzer JNI library
// has been loaded before any such code, which necessarily belongs to the fuzz
// target, is executed and thus don't need NULL checks.
#define DEFINE_TRACE_HOOK(name, params, args)                                \
  typedef void (*trace_##name##_t)(void *, UNWRAP_VA_ARGS params);           \
  static _Atomic trace_##name##_t trace_##name##_with_pc;                    \
                                                                             \
  __attribute__((visibility("default"))) void __sanitizer_cov_trace_##name(  \
      UNWRAP_VA_ARGS params) {                                               \
    trace_##name##_t hook =                                                  \
        atomic_load_explicit(&trace_##name##_with_pc, memory_order_relaxed); \
    hook(GET_CALLER_PC(), UNWRAP_VA_ARGS args);                              \
  }

#define INIT_TRACE_HOOK(handle, name)   \
  atomic_store(&trace_##name##_with_pc, \
               dlsym(handle, "__sanitizer_cov_trace_" #name "_with_pc"))

DEFINE_TRACE_HOOK(cmp1, (uint8_t arg1, uint8_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(cmp2, (uint16_t arg1, uint16_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(cmp4, (uint32_t arg1, uint32_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(cmp8, (uint64_t arg1, uint64_t arg2), (arg1, arg2));

DEFINE_TRACE_HOOK(const_cmp1, (uint8_t arg1, uint8_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(const_cmp2, (uint16_t arg1, uint16_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(const_cmp4, (uint32_t arg1, uint32_t arg2), (arg1, arg2));
DEFINE_TRACE_HOOK(const_cmp8, (uint64_t arg1, uint64_t arg2), (arg1, arg2));

DEFINE_TRACE_HOOK(switch, (uint64_t val, uint64_t *cases), (val, cases));

DEFINE_TRACE_HOOK(div4, (uint32_t arg), (arg))
DEFINE_TRACE_HOOK(div8, (uint64_t arg), (arg))

DEFINE_TRACE_HOOK(gep, (uintptr_t arg), (arg))

DEFINE_TRACE_HOOK(pc_indir, (uintptr_t arg), (arg))

typedef void (*cov_8bit_counters_init_t)(uint8_t *, uint8_t *);
static _Atomic cov_8bit_counters_init_t cov_8bit_counters_init;
typedef void (*cov_pcs_init_t)(const uintptr_t *, const uintptr_t *);
static _Atomic cov_pcs_init_t cov_pcs_init;

__attribute__((visibility("default"))) void __sanitizer_cov_8bit_counters_init(
    uint8_t *start, uint8_t *end) {
  cov_8bit_counters_init_t init =
      atomic_load_explicit(&cov_8bit_counters_init, memory_order_relaxed);
  init(start, end);
}

__attribute__((visibility("default"))) void __sanitizer_cov_pcs_init(
    const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
  cov_pcs_init_t init =
      atomic_load_explicit(&cov_pcs_init, memory_order_relaxed);
  init(pcs_beg, pcs_end);
}

// TODO: This is never updated and thus doesn't provide any information to the
//  fuzzer.
__attribute__((
    visibility("default"))) _Thread_local uintptr_t __sancov_lowest_stack = 0;

__attribute__((visibility("default"))) void jazzer_preload_init(void *handle) {
  INIT_LIBC_HOOK(handle, bcmp);
  INIT_LIBC_HOOK(handle, memcmp);
  INIT_LIBC_HOOK(handle, strncmp);
  INIT_LIBC_HOOK(handle, strcmp);
  INIT_LIBC_HOOK(handle, strncasecmp);
  INIT_LIBC_HOOK(handle, strcasecmp);
  INIT_LIBC_HOOK(handle, strstr);
  INIT_LIBC_HOOK(handle, strcasestr);
  INIT_LIBC_HOOK(handle, memmem);

  INIT_TRACE_HOOK(handle, cmp1);
  INIT_TRACE_HOOK(handle, cmp2);
  INIT_TRACE_HOOK(handle, cmp4);
  INIT_TRACE_HOOK(handle, cmp8);

  INIT_TRACE_HOOK(handle, const_cmp1);
  INIT_TRACE_HOOK(handle, const_cmp2);
  INIT_TRACE_HOOK(handle, const_cmp4);
  INIT_TRACE_HOOK(handle, const_cmp8);

  INIT_TRACE_HOOK(handle, switch);

  INIT_TRACE_HOOK(handle, div4);
  INIT_TRACE_HOOK(handle, div8);

  INIT_TRACE_HOOK(handle, gep);

  INIT_TRACE_HOOK(handle, pc_indir);

  atomic_store(&cov_8bit_counters_init,
               dlsym(handle, "__sanitizer_cov_8bit_counters_init"));
  atomic_store(&cov_pcs_init, dlsym(handle, "__sanitizer_cov_pcs_init"));
}
