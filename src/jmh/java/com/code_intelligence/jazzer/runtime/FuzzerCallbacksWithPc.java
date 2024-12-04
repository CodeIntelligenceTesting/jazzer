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

/**
 * Unoptimized implementation of the libFuzzer callbacks that use the trampoline construction to
 * inject fake PCs.
 */
public final class FuzzerCallbacksWithPc {
  static {
    RulesJni.loadLibrary("fuzzer_callbacks", FuzzerCallbacksWithPc.class);
  }

  static native void traceCmpInt(int arg1, int arg2, int pc);

  static native void traceSwitch(long val, long[] cases, int pc);
}
