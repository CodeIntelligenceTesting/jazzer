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
// translates a runtime argument `fake_pc` in the range [0, 4095) into a call to
// a hook with a fake return address whose lower 12 bits are `fake_pc` up to a
// constant shift. This is achieved by pushing a return address pointing into
// 4096 ret instructions at offset `fake_pc` onto the stack and then jumping
// directly to the address of the hook.

#define REPEAT_4(a) a a a a

#define REPEAT_16(a) REPEAT_4(REPEAT_4(a))

#define REPEAT_4096(a) REPEAT_16(REPEAT_16(REPEAT_16(a)))

// Call the function at address `func` with arguments `arg1` and `arg2` while
// ensuring that the return address is `fake_pc` up to a globally constant
// offset.
__attribute__((noinline)) void trampoline(uint64_t arg1, uint64_t arg2,
                                          void *func, uint16_t fake_pc) {
  // arg1 and arg2 have to be forwarded according to the x64 calling convention.
  // We also fix func and fake_pc to their registers so that we can safely use
  // rax below.
  [[maybe_unused]] register uint64_t arg1_loc asm("rdi") = arg1;
  [[maybe_unused]] register uint64_t arg2_loc asm("rsi") = arg2;
  [[maybe_unused]] register void *func_loc asm("rdx") = func;
  [[maybe_unused]] register uint64_t fake_pc_loc asm("rcx") = fake_pc;
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
      // Append a sled of 2^12=4096 ret instructions.
      "ret_sled: \n\t" REPEAT_4096("ret \n\t")
      :
      : "r"(arg1_loc),
        "r"(arg2_loc), [func] "r"(func_loc), [fake_pc] "r"(fake_pc_loc)
      : "memory"
      : end_of_function);

end_of_function:
  return;
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

// Masks any address down to its lower 12 bits.
__attribute__((always_inline)) inline uint16_t caller_pc_to_fake_pc(
    const void *caller_pc) {
  return reinterpret_cast<uintptr_t>(caller_pc) & 0xFFFu;
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
