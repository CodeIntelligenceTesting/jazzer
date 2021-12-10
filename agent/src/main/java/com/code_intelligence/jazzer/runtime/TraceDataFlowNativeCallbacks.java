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

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.utils.Utils;
import java.lang.reflect.Executable;

@SuppressWarnings("unused")
final public class TraceDataFlowNativeCallbacks {
  /* trace-cmp */
  // Calls: void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
  public static native void traceCmpInt(int arg1, int arg2, int pc);

  // Calls: void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2);
  public static native void traceConstCmpInt(int arg1, int arg2, int pc);

  // Calls: void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
  public static native void traceCmpLong(long arg1, long arg2, int pc);

  // Calls: void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases);
  public static native void traceSwitch(long val, long[] cases, int pc);

  // Calls: void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *b1, const void *b2,
  // size_t n, int result);
  public static native void traceMemcmp(byte[] b1, byte[] b2, int result, int pc);

  // Calls: void __sanitizer_weak_hook_strcmp(void *called_pc, const char *s1, const char *s2, int
  // result);
  public static native void traceStrcmp(String s1, String s2, int result, int pc);

  // Calls: void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1, const char *s2, char
  // *result);
  public static native void traceStrstr(String s1, String s2, int pc);

  /* trace-div */
  // Calls: void __sanitizer_cov_trace_div4(uint32_t Val);
  public static native void traceDivInt(int val, int pc);

  // Calls: void __sanitizer_cov_trace_div8(uint64_t Val);
  public static native void traceDivLong(long val, int pc);

  /* trace-gep */
  // Calls: void __sanitizer_cov_trace_gep(uintptr_t Idx);
  public static native void traceGep(long val, int pc);

  /* indirect-calls */
  // Calls: void __sanitizer_cov_trace_pc_indir(uintptr_t Callee);
  private static native void tracePcIndir(int callee, int caller);

  public static void traceReflectiveCall(Executable callee, int pc) {
    String className = callee.getDeclaringClass().getCanonicalName();
    String executableName = callee.getName();
    String descriptor = Utils.getDescriptor(callee);
    tracePcIndir(Utils.simpleFastHash(className, executableName, descriptor), pc);
  }

  public static int traceCmpLongWrapper(long arg1, long arg2, int pc) {
    traceCmpLong(arg1, arg2, pc);
    // Long.compare serves as a substitute for the lcmp opcode, which can't be used directly
    // as the stack layout required for the call can't be achieved without local variables.
    return Long.compare(arg1, arg2);
  }

  // The caller has to ensure that arg1 and arg2 have the same class.
  public static void traceGenericCmp(Object arg1, Object arg2, int pc) {
    if (arg1 instanceof String) {
      traceStrcmp((String) arg1, (String) arg2, 1, pc);
    } else if (arg1 instanceof Integer || arg1 instanceof Short || arg1 instanceof Byte
        || arg1 instanceof Character) {
      traceCmpInt((int) arg1, (int) arg2, pc);
    } else if (arg1 instanceof Long) {
      traceCmpLong((long) arg1, (long) arg2, pc);
    } else if (arg1 instanceof byte[]) {
      traceMemcmp((byte[]) arg1, (byte[]) arg2, 1, pc);
    }
  }

  public static native void handleLibraryLoad();
}
