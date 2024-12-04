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
 * The native functions used by FuzzTargetRunner.
 *
 * <p>This class has to be loaded by the bootstrap class loader since the native library it loads
 * links in libFuzzer and the Java hooks, which have to be on the bootstrap path so that they are
 * seen by Java standard library classes, need to be able to call native libFuzzer callbacks.
 */
public class FuzzTargetRunnerNatives {
  static {
    if (!Constants.IS_ANDROID && FuzzTargetRunnerNatives.class.getClassLoader() != null) {
      throw new IllegalStateException(
          "FuzzTargetRunnerNatives must be loaded in the bootstrap loader");
    }
    RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
  }

  public static native int startLibFuzzer(
      byte[][] args, Class<?> runner, boolean useMutatorFramework);

  public static native void printAndDumpCrashingInput();

  public static native void temporarilyDisableLibfuzzerExitHook();
}
