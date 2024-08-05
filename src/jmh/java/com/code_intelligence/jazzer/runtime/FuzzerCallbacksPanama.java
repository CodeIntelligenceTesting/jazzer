/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import com.github.fmeum.rules_jni.RulesJni;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.FunctionDescriptor;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SymbolLookup;

/**
 * Pure-Java implementation of the fuzzer callbacks backed by Project Panama (requires JDK 16+). To
 * include the implementation in the benchmark on a supported JDK, uncomment the relevant lines in
 * BUILD.bazel.
 */
public class FuzzerCallbacksPanama {
  static {
    RulesJni.loadLibrary("fuzzer_callbacks", FuzzerCallbacks.class);
  }

  private static final MethodHandle traceCmp4 =
      CLinker.getInstance()
          .downcallHandle(
              SymbolLookup.loaderLookup().lookup("__sanitizer_cov_trace_cmp4").get(),
              MethodType.methodType(void.class, int.class, int.class),
              FunctionDescriptor.ofVoid(CLinker.C_INT, CLinker.C_INT));
  private static final MethodHandle traceSwitch =
      CLinker.getInstance()
          .downcallHandle(
              SymbolLookup.loaderLookup().lookup("__sanitizer_cov_trace_switch").get(),
              MethodType.methodType(void.class, long.class, MemoryAddress.class),
              FunctionDescriptor.ofVoid(CLinker.C_LONG, CLinker.C_POINTER));

  static void traceCmpInt(int arg1, int arg2, int pc) throws Throwable {
    traceCmp4.invokeExact(arg1, arg2);
  }

  static void traceCmpSwitch(long val, long[] cases, int pc) throws Throwable {
    try (ResourceScope scope = ResourceScope.newConfinedScope()) {
      MemorySegment nativeCopy =
          MemorySegment.allocateNative(
              MemoryLayout.sequenceLayout(cases.length, CLinker.C_LONG), scope);
      nativeCopy.copyFrom(MemorySegment.ofArray(cases));
      traceSwitch.invokeExact(val, nativeCopy.address());
    }
  }
}
