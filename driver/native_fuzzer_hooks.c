// Copyright 2022 Code Intelligence GmbH
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
 * forward to the symbols provided by the Jazzer driver JNI library once it has
 * been loaded.
 *
 * Native libraries instrumented for fuzzing include references to fuzzer hooks
 * that are resolved by the dynamic linker. Sanitizers such as ASan provide weak
 * definitions of these symbols, but the dynamic linker doesn't distinguish
 * between weak and strong symbols and thus wouldn't ever resolve them against
 * the strong definitions provided by the Jazzer driver JNI library.
 * Furthermore, libc functions can only be overridden in the native driver
 * executable, which is the only binary that comes before the actual libc in the
 * dynamic linker search order.
 */

#define _GNU_SOURCE  // for RTLD_NEXT
#include <dlfcn.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

#define GET_CALLER_PC() __builtin_return_address(0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

typedef int (*bcmp_t)(const void *, const void *, size_t);
static _Atomic bcmp_t bcmp_real;
typedef void (*bcmp_hook_t)(void *, const void *, const void *, size_t, int);
static _Atomic bcmp_hook_t bcmp_hook;

typedef int (*memcmp_t)(const void *, const void *, size_t);
static _Atomic memcmp_t memcmp_real;
typedef void (*memcmp_hook_t)(void *, const void *, const void *, size_t, int);
static _Atomic memcmp_hook_t memcmp_hook;

typedef int (*strncmp_t)(const char *, const char *, size_t);
static _Atomic strncmp_t strncmp_real;
typedef void (*strncmp_hook_t)(void *, const char *, const char *, size_t, int);
static _Atomic strncmp_hook_t strncmp_hook;

typedef int (*strcmp_t)(const char *, const char *);
static _Atomic strcmp_t strcmp_real;
typedef void (*strcmp_hook_t)(void *, const char *, const char *, int);
static _Atomic strcmp_hook_t strcmp_hook;

typedef int (*strncasecmp_t)(const char *, const char *, size_t);
static _Atomic strncasecmp_t strncasecmp_real;
typedef void (*strncasecmp_hook_t)(void *, const char *, const char *, size_t,
                                   int);
static _Atomic strncasecmp_hook_t strncasecmp_hook;

typedef int (*strcasecmp_t)(const char *, const char *);
static _Atomic strcasecmp_t strcasecmp_real;
typedef void (*strcasecmp_hook_t)(void *, const char *, const char *, int);
static _Atomic strcasecmp_hook_t strcasecmp_hook;

typedef char *(*strstr_t)(const char *, const char *);
static _Atomic strstr_t strstr_real;
typedef void (*strstr_hook_t)(void *, const char *, const char *, char *);
static _Atomic strstr_hook_t strstr_hook;

typedef char *(*strcasestr_t)(const char *, const char *);
static _Atomic strcasestr_t strcasestr_real;
typedef void (*strcasestr_hook_t)(void *, const char *, const char *, char *);
static _Atomic strcasestr_hook_t strcasestr_hook;

typedef void *(*memmem_t)(const void *, size_t, const void *, size_t);
static _Atomic memmem_t memmem_real;
typedef void (*memmem_hook_t)(void *, const void *, size_t, const void *,
                              size_t, void *);
static _Atomic memmem_hook_t memmem_hook;

typedef void (*cov_8bit_counters_init_t)(uint8_t *, uint8_t *);
static _Atomic cov_8bit_counters_init_t cov_8bit_counters_init;
typedef void (*cov_pcs_init_t)(const uintptr_t *, const uintptr_t *);
static _Atomic cov_pcs_init_t cov_pcs_init;

typedef void (*trace_cmp1_t)(void *, uint8_t, uint8_t);
static _Atomic trace_cmp1_t trace_cmp1_with_pc;
typedef void (*trace_cmp2_t)(void *, uint16_t, uint16_t);
static _Atomic trace_cmp2_t trace_cmp2_with_pc;
typedef void (*trace_cmp4_t)(void *, uint32_t, uint32_t);
static _Atomic trace_cmp4_t trace_cmp4_with_pc;
typedef void (*trace_cmp8_t)(void *, uint64_t, uint64_t);
static _Atomic trace_cmp8_t trace_cmp8_with_pc;

typedef void (*trace_const_cmp1_t)(void *, uint8_t, uint8_t);
static _Atomic trace_const_cmp1_t trace_const_cmp1_with_pc;
typedef void (*trace_const_cmp2_t)(void *, uint16_t, uint16_t);
static _Atomic trace_const_cmp2_t trace_const_cmp2_with_pc;
typedef void (*trace_const_cmp4_t)(void *, uint32_t, uint32_t);
static _Atomic trace_const_cmp4_t trace_const_cmp4_with_pc;
typedef void (*trace_const_cmp8_t)(void *, uint64_t, uint64_t);
static _Atomic trace_const_cmp8_t trace_const_cmp8_with_pc;

typedef void (*trace_switch_t)(void *, uint64_t, uint64_t *);
static _Atomic trace_switch_t trace_switch_with_pc;

typedef void (*trace_div4_t)(void *, uint32_t);
static _Atomic trace_div4_t trace_div4_with_pc;
typedef void (*trace_div8_t)(void *, uint64_t);
static _Atomic trace_div8_t trace_div8_with_pc;

typedef void (*trace_gep_t)(void *, uintptr_t);
static _Atomic trace_gep_t trace_gep_with_pc;

typedef void (*trace_pc_indir_t)(void *, uintptr_t);
static _Atomic trace_pc_indir_t trace_pc_indir_with_pc;

__attribute__((visibility("default"))) void jazzer_initialize_native_hooks(
    void *handle) {
  atomic_store(&bcmp_hook, dlsym(handle, "__sanitizer_weak_hook_bcmp"));
  atomic_store(&memcmp_hook, dlsym(handle, "__sanitizer_weak_hook_memcmp"));
  atomic_store(&strncmp_hook, dlsym(handle, "__sanitizer_weak_hook_strncmp"));
  atomic_store(&strcmp_hook, dlsym(handle, "__sanitizer_weak_hook_strcmp"));
  atomic_store(&strncasecmp_hook,
               dlsym(handle, "__sanitizer_weak_hook_strncasecmp"));
  atomic_store(&strcasecmp_hook,
               dlsym(handle, "__sanitizer_weak_hook_strcasecmp"));
  atomic_store(&strstr_hook, dlsym(handle, "__sanitizer_weak_hook_strstr"));
  atomic_store(&strcasestr_hook,
               dlsym(handle, "__sanitizer_weak_hook_strcasestr"));
  atomic_store(&memmem_hook, dlsym(handle, "__sanitizer_weak_hook_memmem"));

  atomic_store(&cov_8bit_counters_init,
               dlsym(handle, "__sanitizer_cov_8bit_counters_init"));
  atomic_store(&cov_pcs_init, dlsym(handle, "__sanitizer_cov_pcs_init"));

  atomic_store(&trace_cmp1_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_cmp1_with_pc"));
  atomic_store(&trace_cmp2_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_cmp2_with_pc"));
  atomic_store(&trace_cmp4_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_cmp4_with_pc"));
  atomic_store(&trace_cmp8_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_cmp8_with_pc"));

  atomic_store(&trace_const_cmp1_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_const_cmp1_with_pc"));
  atomic_store(&trace_const_cmp2_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_const_cmp2_with_pc"));
  atomic_store(&trace_const_cmp4_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_const_cmp4_with_pc"));
  atomic_store(&trace_const_cmp8_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_const_cmp8_with_pc"));

  atomic_store(&trace_switch_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_switch_with_pc"));

  atomic_store(&trace_div4_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_div4_with_pc"));
  atomic_store(&trace_div8_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_div8_with_pc"));

  atomic_store(&trace_gep_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_gep_with_pc"));

  atomic_store(&trace_pc_indir_with_pc,
               dlsym(handle, "__sanitizer_cov_trace_pc_indir_with_pc"));
}

// Alternate definitions for libc functions mimicking those that libFuzzer would
// provide if it were part of the native driver executable. All these functions
// invoke the real libc function loaded from the next library in search order
// (usually libc itself).
// Function pointers have to be loaded and stored atomically even if libc
// functions are invoked from different threads, but we do not need any
// synchronization guarantees - in the worst case, we will non-deterministically
// lose a few hook invocations.

__attribute__((visibility("default"))) int bcmp(const void *s1, const void *s2,
                                                size_t n) {
  bcmp_t bcmp_real_local =
      atomic_load_explicit(&bcmp_real, memory_order_relaxed);
  if (UNLIKELY(bcmp_real_local == NULL)) {
    bcmp_real_local = dlsym(RTLD_NEXT, "bcmp");
    atomic_store_explicit(&bcmp_real, bcmp_real_local, memory_order_relaxed);
  }

  int result = bcmp_real_local(s1, s2, n);
  bcmp_hook_t hook = atomic_load_explicit(&bcmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, n, result);
  }
  return result;
}

__attribute__((visibility("default"))) int memcmp(const void *s1,
                                                  const void *s2, size_t n) {
  memcmp_t memcmp_real_local =
      atomic_load_explicit(&memcmp_real, memory_order_relaxed);
  if (UNLIKELY(memcmp_real_local == NULL)) {
    memcmp_real_local = dlsym(RTLD_NEXT, "memcmp");
    atomic_store_explicit(&memcmp_real, memcmp_real_local,
                          memory_order_relaxed);
  }

  int result = memcmp_real_local(s1, s2, n);
  memcmp_hook_t hook = atomic_load_explicit(&memcmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, n, result);
  }
  return result;
}

__attribute__((visibility("default"))) int strncmp(const char *s1,
                                                   const char *s2, size_t n) {
  strncmp_t strncmp_real_local =
      atomic_load_explicit(&strncmp_real, memory_order_relaxed);
  if (UNLIKELY(strncmp_real_local == NULL)) {
    strncmp_real_local = dlsym(RTLD_NEXT, "strncmp");
    atomic_store_explicit(&strncmp_real, strncmp_real_local,
                          memory_order_relaxed);
  }

  int result = strncmp_real_local(s1, s2, n);
  strncmp_hook_t hook =
      atomic_load_explicit(&strncmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, n, result);
  }
  return result;
}

__attribute__((visibility("default"))) int strncasecmp(const char *s1,
                                                       const char *s2,
                                                       size_t n) {
  strncasecmp_t strncasecmp_real_local =
      atomic_load_explicit(&strncasecmp_real, memory_order_relaxed);
  if (UNLIKELY(strncasecmp_real_local == NULL)) {
    strncasecmp_real_local = dlsym(RTLD_NEXT, "strncasecmp");
    atomic_store_explicit(&strncasecmp_real, strncasecmp_real_local,
                          memory_order_relaxed);
  }

  int result = strncasecmp_real_local(s1, s2, n);
  strncasecmp_hook_t hook =
      atomic_load_explicit(&strncasecmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, n, result);
  }
  return result;
}

__attribute__((visibility("default"))) int strcmp(const char *s1,
                                                  const char *s2) {
  strcmp_t strcmp_real_local =
      atomic_load_explicit(&strcmp_real, memory_order_relaxed);
  if (UNLIKELY(strcmp_real_local == NULL)) {
    strcmp_real_local = dlsym(RTLD_NEXT, "strcmp");
    atomic_store_explicit(&strcmp_real, strcmp_real_local,
                          memory_order_relaxed);
  }

  int result = strcmp_real_local(s1, s2);
  strcmp_hook_t hook = atomic_load_explicit(&strcmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, result);
  }
  return result;
}

__attribute__((visibility("default"))) int strcasecmp(const char *s1,
                                                      const char *s2) {
  strcasecmp_t strcasecmp_real_local =
      atomic_load_explicit(&strcasecmp_real, memory_order_relaxed);
  if (UNLIKELY(strcasecmp_real_local == NULL)) {
    strcasecmp_real_local = dlsym(RTLD_NEXT, "strcasecmp");
    atomic_store_explicit(&strcasecmp_real, strcasecmp_real_local,
                          memory_order_relaxed);
  }

  int result = strcasecmp_real_local(s1, s2);
  strcasecmp_hook_t hook =
      atomic_load_explicit(&strcasecmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, result);
  }
  return result;
}

__attribute__((visibility("default"))) char *strstr(const char *s1,
                                                    const char *s2) {
  strstr_t strstr_real_local =
      atomic_load_explicit(&strstr_real, memory_order_relaxed);
  if (UNLIKELY(strstr_real_local == NULL)) {
    strstr_real_local = dlsym(RTLD_NEXT, "strstr");
    atomic_store_explicit(&strstr_real, strstr_real_local,
                          memory_order_relaxed);
  }

  char *result = strstr_real_local(s1, s2);
  strstr_hook_t hook = atomic_load_explicit(&strstr_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, result);
  }
  return result;
}

__attribute__((visibility("default"))) char *strcasestr(const char *s1,
                                                        const char *s2) {
  strcasestr_t strcasestr_real_local =
      atomic_load_explicit(&strcasestr_real, memory_order_relaxed);
  if (UNLIKELY(strcasestr_real_local == NULL)) {
    strcasestr_real_local = dlsym(RTLD_NEXT, "strcasestr");
    atomic_store_explicit(&strcasestr_real, strcasestr_real_local,
                          memory_order_relaxed);
  }

  char *result = strcasestr_real_local(s1, s2);
  strcasestr_hook_t hook =
      atomic_load_explicit(&strcasestr_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, s2, result);
  }
  return result;
}

__attribute__((visibility("default"))) void *memmem(const void *s1, size_t n1,
                                                    const void *s2, size_t n2) {
  memmem_t memmem_real_local =
      atomic_load_explicit(&memmem_real, memory_order_relaxed);
  if (UNLIKELY(memmem_real_local == NULL)) {
    memmem_real_local = dlsym(RTLD_NEXT, "memmem");
    atomic_store_explicit(&memmem_real, memmem_real_local,
                          memory_order_relaxed);
  }

  void *result = memmem_real_local(s1, n1, s2, n2);
  memmem_hook_t hook = atomic_load_explicit(&memmem_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(GET_CALLER_PC(), s1, n1, s2, n2, result);
  }
  return result;
}

// The __sanitizer_cov_trace_* family of functions is only invoked from code
// compiled with -fsanitize=fuzzer. We can assume that the Jazzer JNI library
// has been loaded before any such code, which necessarily belongs to the fuzz
// target, is executed and thus don't need NULL checks.

__attribute__((visibility("default"))) void __sanitizer_cov_trace_cmp1(
    uint8_t arg1, uint8_t arg2) {
  trace_cmp1_t hook =
      atomic_load_explicit(&trace_cmp1_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_cmp2(
    uint16_t arg1, uint16_t arg2) {
  trace_cmp2_t hook =
      atomic_load_explicit(&trace_cmp2_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_cmp4(
    uint32_t arg1, uint32_t arg2) {
  trace_cmp4_t hook =
      atomic_load_explicit(&trace_cmp4_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_cmp8(
    uint64_t arg1, uint64_t arg2) {
  trace_cmp8_t hook =
      atomic_load_explicit(&trace_cmp8_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_const_cmp1(
    uint8_t arg1, uint8_t arg2) {
  trace_const_cmp1_t hook =
      atomic_load_explicit(&trace_const_cmp1_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_const_cmp2(
    uint16_t arg1, uint16_t arg2) {
  trace_const_cmp2_t hook =
      atomic_load_explicit(&trace_const_cmp2_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_const_cmp4(
    uint32_t arg1, uint32_t arg2) {
  trace_const_cmp4_t hook =
      atomic_load_explicit(&trace_const_cmp4_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_const_cmp8(
    uint64_t arg1, uint64_t arg2) {
  trace_const_cmp8_t hook =
      atomic_load_explicit(&trace_const_cmp8_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), arg1, arg2);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_switch(
    uint64_t val, uint64_t *cases) {
  trace_switch_t hook =
      atomic_load_explicit(&trace_switch_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), val, cases);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_div4(
    uint32_t val) {
  trace_div4_t hook =
      atomic_load_explicit(&trace_div4_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), val);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_div8(
    uint64_t val) {
  trace_div8_t hook =
      atomic_load_explicit(&trace_div8_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), val);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_gep(
    uintptr_t idx) {
  trace_gep_t hook =
      atomic_load_explicit(&trace_gep_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), idx);
}

__attribute__((visibility("default"))) void __sanitizer_cov_trace_pc_indir(
    uintptr_t callee) {
  trace_pc_indir_t hook =
      atomic_load_explicit(&trace_pc_indir_with_pc, memory_order_relaxed);
  hook(GET_CALLER_PC(), callee);
}

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

// The __sanitizer_weak_hook_* family of functions can be invoked early on macOS
// and thus requires NULL checks.

__attribute__((visibility("default"))) void __sanitizer_weak_hook_memcmp(
    void *called_pc, const void *s1, const void *s2, size_t n, int result) {
  memcmp_hook_t hook = atomic_load_explicit(&memcmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, n, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strncmp(
    void *called_pc, const void *s1, const void *s2, size_t n, int result) {
  strncmp_hook_t hook =
      atomic_load_explicit(&strncmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, n, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strcmp(
    void *called_pc, const void *s1, const void *s2, int result) {
  strcmp_hook_t hook = atomic_load_explicit(&strcmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strncasecmp(
    void *called_pc, const void *s1, const void *s2, size_t n, int result) {
  strncasecmp_hook_t hook =
      atomic_load_explicit(&strncasecmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, n, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strcasecmp(
    void *called_pc, const void *s1, const void *s2, int result) {
  strcasecmp_hook_t hook =
      atomic_load_explicit(&strcasecmp_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strstr(
    void *called_pc, const void *s1, const void *s2, char *result) {
  strstr_hook_t hook = atomic_load_explicit(&strstr_hook, memory_order_relaxed);
  if (LIKELY(hook != NULL)) {
    hook(called_pc, s1, s2, result);
  }
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_strcasestr(
    void *called_pc, const void *s1, const void *s2, char *result) {
  strcasestr_hook_t hook =
      atomic_load_explicit(&strstr_hook, memory_order_relaxed);
  hook(called_pc, s1, s2, result);
}

__attribute__((visibility("default"))) void __sanitizer_weak_hook_memmem(
    void *called_pc, const void *s1, size_t len1, const void *s2, size_t len2,
    void *result) {
  memmem_hook_t hook = atomic_load_explicit(&memmem_hook, memory_order_relaxed);
  hook(called_pc, s1, len1, s2, len2, result);
}
