/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.runtime;

import com.github.fmeum.rules_jni.RulesJni;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.objectweb.asm.Type;

@SuppressWarnings("unused")
public final class TraceDataFlowNativeCallbacks {
  // Note that we are not encoding as modified UTF-8 here: The FuzzedDataProvider transparently
  // converts CESU8 into modified UTF-8 by coding null bytes on two bytes. Since the fuzzer is more
  // likely to insert literal null bytes, having both the fuzzer input and the reported string
  // comparisons be CESU8 should perform even better than the current implementation using modified
  // UTF-8.
  private static final Charset FUZZED_DATA_CHARSET = Charset.forName("CESU8");

  static {
    RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
  }

  // It is possible for RulesJni#loadLibrary to trigger a hook even though it isn't instrumented if
  // it uses regexes, which it does with at least some JDKs due to its use of String#format. This
  // led to exceptions in the past when the hook ended up calling traceStrcmp or traceStrstr before
  // the static initializer was run: FUZZED_DATA_CHARSET used to be initialized after the call and
  // thus still had the value null when encodeForLibFuzzer was called, resulting in an NPE in
  // String#getBytes(Charset). Just switching the order may actually make this bug worse: It could
  // now lead to traceMemcmp being called before the native library has been loaded. We guard
  // against this by making the hooks noops when static initialization of this class hasn't
  // completed yet.
  private static final boolean NATIVE_INITIALIZED = true;

  public static native void traceMemcmp(byte[] b1, byte[] b2, int result, int pc);

  public static void traceStrcmp(String s1, String s2, int result, int pc) {
    if (NATIVE_INITIALIZED) {
      traceMemcmp(encodeForLibFuzzer(s1), encodeForLibFuzzer(s2), result, pc);
    }
  }

  public static void traceStrstr(String s1, String s2, int pc) {
    if (NATIVE_INITIALIZED) {
      traceStrstr0(encodeForLibFuzzer(s2), pc);
    }
  }

  public static void traceReflectiveCall(Executable callee, int pc) {
    String className = callee.getDeclaringClass().getCanonicalName();
    String executableName = callee.getName();
    String descriptor;
    if (callee instanceof Method) {
      descriptor = Type.getMethodDescriptor((Method) callee);
    } else {
      descriptor = Type.getConstructorDescriptor((Constructor<?>) callee);
    }
    tracePcIndir(Arrays.hashCode(new String[] {className, executableName, descriptor}), pc);
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

  /* trace-cmp */
  public static native void traceCmpInt(int arg1, int arg2, int pc);

  public static native void traceConstCmpInt(int arg1, int arg2, int pc);

  public static native void traceCmpLong(long arg1, long arg2, int pc);

  public static native void traceSwitch(long val, long[] cases, int pc);

  /* trace-div */
  public static native void traceDivInt(int val, int pc);

  public static native void traceDivLong(long val, int pc);

  /* trace-gep */
  public static native void traceGep(long val, int pc);

  /* indirect-calls */
  public static native void tracePcIndir(int callee, int caller);

  public static native void handleLibraryLoad();

  private static byte[] encodeForLibFuzzer(String str) {
    // libFuzzer string hooks only ever consume the first 64 bytes, so we can definitely cut the
    // string off after 64 characters.
    return str.substring(0, Math.min(str.length(), 64)).getBytes(FUZZED_DATA_CHARSET);
  }

  private static native void traceStrstr0(byte[] needle, int pc);
}
