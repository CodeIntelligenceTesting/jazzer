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
import java.nio.charset.Charset;

@SuppressWarnings("unused")
final public class TraceDataFlowNativeCallbacks {
  // Making this static final ensures that the JIT will eliminate the dead branch of a construct
  // such as:
  // if (USE_FAKE_PCS) ... else ...
  private static final boolean USE_FAKE_PCS = useFakePcs();
  // Note that we are not encoding as modified UTF-8 here: The FuzzedDataProvider transparently
  // converts CESU8 into modified UTF-8 by coding null bytes on two bytes. Since the fuzzer is more
  // likely to insert literal null bytes, having both the fuzzer input and the reported string
  // comparisons be CESU8 should perform even better than the current implementation using modified
  // UTF-8.
  private static final Charset FUZZED_DATA_CHARSET = Charset.forName("CESU8");

  /* trace-cmp */
  public static void traceCmpInt(int arg1, int arg2, int pc) {
    if (USE_FAKE_PCS) {
      traceCmpIntWithPc(arg1, arg2, pc);
    } else {
      traceCmpInt(arg1, arg2);
    }
  }

  public static void traceConstCmpInt(int arg1, int arg2, int pc) {
    if (USE_FAKE_PCS) {
      traceConstCmpIntWithPc(arg1, arg2, pc);
    } else {
      traceConstCmpInt(arg1, arg2);
    }
  }

  public static void traceCmpLong(long arg1, long arg2, int pc) {
    if (USE_FAKE_PCS) {
      traceCmpLongWithPc(arg1, arg2, pc);
    } else {
      traceCmpLong(arg1, arg2);
    }
  }

  public static void traceSwitch(long val, long[] cases, int pc) {
    if (USE_FAKE_PCS) {
      traceSwitchWithPc(val, cases, pc);
    } else {
      traceSwitch(val, cases);
    }
  }

  public static native void traceMemcmp(byte[] b1, byte[] b2, int result, int pc);

  public static void traceStrcmp(String s1, String s2, int result, int pc) {
    traceMemcmp(encodeForLibFuzzer(s1), encodeForLibFuzzer(s2), result, pc);
  }

  public static void traceStrstr(String s1, String s2, int pc) {
    traceStrstr0(encodeForLibFuzzer(s2), pc);
  }

  /* trace-div */
  public static void traceDivInt(int val, int pc) {
    if (USE_FAKE_PCS) {
      traceDivIntWithPc(val, pc);
    } else {
      traceDivInt(val);
    }
  }

  public static void traceDivLong(long val, int pc) {
    if (USE_FAKE_PCS) {
      traceDivLongWithPc(val, pc);
    } else {
      traceDivLong(val);
    }
  }

  /* trace-gep */
  public static void traceGep(long val, int pc) {
    if (USE_FAKE_PCS) {
      traceGepWithPc(val, pc);
    } else {
      traceGep(val);
    }
  }

  /* indirect-calls */
  public static void tracePcIndir(int callee, int caller) {
    if (!USE_FAKE_PCS) {
      // Without fake PCs, tracePcIndir will not record the relation between callee and pc, which
      // makes it useless.
      return;
    }
    tracePcIndir0(callee, caller);
  }

  public static void traceReflectiveCall(Executable callee, int pc) {
    if (!USE_FAKE_PCS) {
      // Without fake PCs, tracePcIndir will not record the relation between callee and pc, which
      // makes it useless.
      return;
    }
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
    if (arg1 instanceof CharSequence) {
      traceStrcmp(arg1.toString(), arg2.toString(), 1, pc);
    } else if (arg1 instanceof Integer) {
      traceCmpInt((int) arg1, (int) arg2, pc);
    } else if (arg1 instanceof Long) {
      traceCmpLong((long) arg1, (long) arg2, pc);
    } else if (arg1 instanceof Short) {
      traceCmpInt((short) arg1, (short) arg2, pc);
    } else if (arg1 instanceof Byte) {
      traceCmpInt((byte) arg1, (byte) arg2, pc);
    } else if (arg1 instanceof Character) {
      traceCmpInt((char) arg1, (char) arg2, pc);
    } else if (arg1 instanceof Number) {
      traceCmpLong(((Number) arg1).longValue(), ((Number) arg2).longValue(), pc);
    } else if (arg1 instanceof byte[]) {
      traceMemcmp((byte[]) arg1, (byte[]) arg2, 1, pc);
    }
  }

  public static native void handleLibraryLoad();

  private static byte[] encodeForLibFuzzer(String str) {
    // libFuzzer string hooks only ever consume the first 64 bytes, so we can definitely cut the
    // string off after 64 characters.
    return str.substring(0, Math.min(str.length(), 64)).getBytes(FUZZED_DATA_CHARSET);
  }

  private static boolean useFakePcs() {
    String rawFakePcs = System.getProperty("jazzer.fake_pcs");
    if (rawFakePcs == null) {
      return false;
    }
    return Boolean.parseBoolean(rawFakePcs);
  }

  private static native void traceStrstr0(byte[] needle, int pc);

  private static native void traceCmpInt(int arg1, int arg2);
  private static native void traceCmpIntWithPc(int arg1, int arg2, int pc);
  private static native void traceConstCmpInt(int arg1, int arg2);
  private static native void traceConstCmpIntWithPc(int arg1, int arg2, int pc);
  private static native void traceCmpLong(long arg1, long arg2);
  private static native void traceCmpLongWithPc(long arg1, long arg2, int pc);
  private static native void traceSwitch(long val, long[] cases);
  private static native void traceSwitchWithPc(long val, long[] cases, int pc);
  private static native void traceDivInt(int val);
  private static native void traceDivIntWithPc(int val, int pc);
  private static native void traceDivLong(long val);
  private static native void traceDivLongWithPc(long val, int pc);
  private static native void traceGep(long val);
  private static native void traceGepWithPc(long val, int pc);
  private static native void tracePcIndir0(int callee, int caller);
}
