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

package com.code_intelligence.jazzer.android;

import com.code_intelligence.jazzer.utils.Log;
import com.github.fmeum.rules_jni.RulesJni;

/**
 * Loads Android tooling library and registers native functions.
 */
public class AndroidRuntime {
  private static final String DO_NOT_INITIALIZE = "use_none";
  private static final String FUZZ_DIR = "/data/fuzz/";
  private static final String PLATFORM_LIB_DIRS = ":/system/lib64/:/apex/com.android.i18n@1/lib64/";

  public static void initialize(String runtimeLibs) {
    if (runtimeLibs == null) {
      return;
    }

    RulesJni.loadLibrary("jazzer_android_tooling", "/com/code_intelligence/jazzer/driver");
    if (runtimeLibs.equals(DO_NOT_INITIALIZE)) {
      Log.warn("Android Runtime (ART) is not being initialized for this fuzzer.");
    } else {
      registerNatives();
    }
  };

  /**
   * Returns a command to set the classpath for fuzzing.
   *
   * @return The classpath command.
   */
  public static String getClassPathsCommand() {
    return "export CLASSPATH=" + System.getProperty("java.class.path");
  }

  /**
   * Builds and returns the value to set for LD_LIBRARY_PATH.
   * This value is consumed when launching jazzer on the device
   * and specifies which directories to search for dependencies.
   *
   * @return The string for LD_LIBRARY_PATH.
   */
  public static String getLdLibraryPath() {
    String initOptString = System.getProperty("jazzer.android_init_options");
    if (initOptString.equals(DO_NOT_INITIALIZE) || initOptString.equals("")) {
      return FUZZ_DIR;
    }

    return FUZZ_DIR + PLATFORM_LIB_DIRS;
  }

  private static native int registerNatives();
}
