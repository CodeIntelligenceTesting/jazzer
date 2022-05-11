// Copyright 2021 Code Intelligence GmbH
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

#include "sanitizer_hooks_with_pc.h"

#include <cstddef>
#include <cstdint>

// libFuzzer's compare hooks obtain the caller's address from the compiler
// builtin __builtin_return_adress. Since Java code will invoke the hooks always
// from the same native function, this builtin would always return the same
// value. Internally, the libFuzzer hooks call through to the always inlined
// HandleCmp and thus can't be mimicked without patching libFuzzer.
//
// We solve this problem via an inline assembly trampoline construction that
// translates a runtime argument `fake_pc` in the range [0, 512) into a call to
// a hook with a fake return address whose lower 9 bits are `fake_pc` up to a
// constant shift. This is achieved by pushing a return address pointing into
// 512 ret instructions at offset `fake_pc` onto the stack and then jumping
// directly to the address of the hook.
//
// Note: We only set the lowest 9 bits of the return address since only these
// bits are used by the libFuzzer value profiling mode for integer compares, see
// https://github.com/llvm/llvm-project/blob/704d92607d26e696daba596b72cb70effe79a872/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L390
// as well as
// https://github.com/llvm/llvm-project/blob/704d92607d26e696daba596b72cb70effe79a872/compiler-rt/lib/fuzzer/FuzzerValueBitMap.h#L34
// ValueProfileMap.AddValue() truncates its argument to 16 bits and shifts the
// PC to the left by log_2(128)=7, which means that only the lowest 16 - 7 bits
// of the return address matter. String compare hooks use the lowest 12 bits,
// but take the return address as an argument and thus don't require the
// indirection through a trampoline.

#define REPEAT_2(a) a a

#define REPEAT_8(a) REPEAT_2(REPEAT_2(REPEAT_2(a)))

#define REPEAT_128(a) REPEAT_2(REPEAT_8(REPEAT_8(a)))

#define REPEAT_512(a) REPEAT_8(REPEAT_8(REPEAT_8(a)))

// The first four registers to pass arguments in according to the
// platform-specific x64 calling convention.
#ifdef __aarch64__
#define REG_1 "x0"
#define REG_2 "x1"
#define REG_3 "x2"
#define REG_4 "x3"
#elif _WIN64
#define REG_1 "rcx"
#define REG_2 "rdx"
#define REG_3 "r8"
#define REG_4 "r9"
#else
#define REG_1 "rdi"
#define REG_2 "rsi"
#define REG_3 "rdx"
#define REG_4 "rcx"
#endif

// Call the function at address `func` with arguments `arg1` and `arg2` while
// ensuring that the return address is `fake_pc` up to a globally constant
// offset.
__attribute__((noinline)) void trampoline(uint64_t arg1, uint64_t arg2,
                                          void *func, uint16_t fake_pc) {
  // arg1 and arg2 have to be forwarded according to the calling convention.
  // We also fix func and fake_pc to their registers so that we can safely use
  // rax below.
  [[maybe_unused]] register uint64_t arg1_loc asm(REG_1) = arg1;
  [[maybe_unused]] register uint64_t arg2_loc asm(REG_2) = arg2;
  [[maybe_unused]] register void *func_loc asm(REG_3) = func;
  [[maybe_unused]] register uint64_t fake_pc_loc asm(REG_4) = fake_pc;
#ifdef __aarch64__
  asm volatile(
      // Load address of the ret sled into the default register for the return
      // address (offset of four instructions, which means 16 bytes).
      "adr x30, 16 \n\t"
      // Clear the lowest 2 bits of fake_pc. All arm64 instructions are four
      // bytes long, so we can't get better return address granularity than
      // multiples of 4.
      "and %[fake_pc], %[fake_pc], #0xFFFFFFFFFFFFFFFC \n\t"
      // Add the offset of the fake_pc-th ret (rounded to 0 mod 4 above).
      "add x30, x30, %[fake_pc] \n\t"
      // Call the function by jumping to it and reusing all registers except
      // for the modified return address register r30.
      "br %[func] \n\t"
      // The ret sled for arm64 consists of 128 b instructions jumping to the
      // end of the function. Each instruction is 4 bytes long. The sled thus
      // has the same byte length of 4 * 128 = 512 as the x86_64 sled, but
      // coarser granularity.
      REPEAT_128("b end_of_function\n\t") "end_of_function:\n\t"
      :
      : "r"(arg1_loc),
        "r"(arg2_loc), [func] "r"(func_loc), [fake_pc] "r"(fake_pc_loc)
      : "memory", "x30");
#else
  asm volatile goto(
      // Load RIP-relative address of the end of this function.
      "lea %l[end_of_function](%%rip), %%rax \n\t"
      "push %%rax \n\t"
      // Load RIP-relative address of the ret sled into rax.
      "lea ret_sled(%%rip), %%rax \n\t"
      // Add the offset of the fake_pc-th ret.
      "add %[fake_pc], %%rax \n\t"
      // Push the fake return address pointing to that ret. The hook will return
      // to it and then immediately return to the end of this function.
      "push %%rax \n\t"
      // Call func with the fake return address on the stack.
      // Function arguments arg1 and arg2 are passed unchanged in the registers
      // RDI and RSI as governed by the x64 calling convention.
      "jmp *%[func] \n\t"
      // Append a sled of 2^9=512 ret instructions.
      "ret_sled: \n\t" REPEAT_512("ret \n\t")
      :
      : "r"(arg1_loc),
        "r"(arg2_loc), [func] "r"(func_loc), [fake_pc] "r"(fake_pc_loc)
      : "memory"
      : end_of_function);

end_of_function:
  return;
#endif
}

namespace {
uintptr_t trampoline_offset = 0;
}

void set_trampoline_offset() {
  // Stores the additive inverse of the current return address modulo 0x200u in
  // trampoline_offset.
  trampoline_offset =
      0x200u -
      (reinterpret_cast<uintptr_t>(__builtin_return_address(0)) & 0x1FFu);
}

// Computes the additive shift that needs to be applied to the caller PC by
// caller_pc_to_fake_pc to make caller PC and resulting fake return address
// in their lowest 9 bits. This offset is constant for each binary, but may vary
// based on code generation specifics. By calibrating the trampoline, the fuzzer
// behavior is fully determined by the seed.
__attribute__((constructor)) void CalibrateTrampoline() {
  trampoline(0, 0, reinterpret_cast<void *>(&set_trampoline_offset), 0);
}

// Masks any address down to its lower 9 bits, adjusting for the trampoline
// shift.
__attribute__((always_inline)) inline uint16_t caller_pc_to_fake_pc(
    const void *caller_pc) {
  return (reinterpret_cast<uintptr_t>(caller_pc) + trampoline_offset) & 0x1FFu;
}

// The original hooks exposed by libFuzzer. All of these get the caller's
// address via __builtin_return_address(0).
extern "C" {
void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2);
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases);
void __sanitizer_cov_trace_div4(uint32_t val);
void __sanitizer_cov_trace_div8(uint64_t val);
void __sanitizer_cov_trace_gep(uintptr_t idx);
void __sanitizer_cov_trace_pc_indir(uintptr_t callee);
}
void __sanitizer_cov_trace_cmp4_with_pc(void *caller_pc, uint32_t arg1,
                                        uint32_t arg2) {
  void *trace_cmp4 = reinterpret_cast<void *>(&__sanitizer_cov_trace_cmp4);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(arg1), static_cast<uint64_t>(arg2),
             trace_cmp4, fake_pc);
}

void __sanitizer_cov_trace_cmp8_with_pc(void *caller_pc, uint64_t arg1,
                                        uint64_t arg2) {
  void *trace_cmp8 = reinterpret_cast<void *>(&__sanitizer_cov_trace_cmp8);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(arg1), static_cast<uint64_t>(arg2),
             trace_cmp8, fake_pc);
}

void __sanitizer_cov_trace_switch_with_pc(void *caller_pc, uint64_t val,
                                          uint64_t *cases) {
  void *trace_switch = reinterpret_cast<void *>(&__sanitizer_cov_trace_switch);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(val), reinterpret_cast<uint64_t>(cases),
             trace_switch, fake_pc);
}

void __sanitizer_cov_trace_div4_with_pc(void *caller_pc, uint32_t val) {
  void *trace_div4 = reinterpret_cast<void *>(&__sanitizer_cov_trace_div4);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(val), 0, trace_div4, fake_pc);
}

void __sanitizer_cov_trace_div8_with_pc(void *caller_pc, uint64_t val) {
  void *trace_div8 = reinterpret_cast<void *>(&__sanitizer_cov_trace_div8);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(val), 0, trace_div8, fake_pc);
}

void __sanitizer_cov_trace_gep_with_pc(void *caller_pc, uintptr_t idx) {
  void *trace_gep = reinterpret_cast<void *>(&__sanitizer_cov_trace_gep);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(idx), 0, trace_gep, fake_pc);
}

void __sanitizer_cov_trace_pc_indir_with_pc(void *caller_pc, uintptr_t callee) {
  void *trace_pc_indir =
      reinterpret_cast<void *>(&__sanitizer_cov_trace_pc_indir);
  auto fake_pc = caller_pc_to_fake_pc(caller_pc);
  trampoline(static_cast<uint64_t>(callee), 0, trace_pc_indir, fake_pc);
}
