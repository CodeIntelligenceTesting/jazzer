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

package com.code_intelligence.jazzer.android;

import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;

import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.utils.Log;
import com.github.fmeum.rules_jni.RulesJni;

/** Loads Android tooling library and registers native functions. */
public class AndroidRuntime {
  private static final String DO_NOT_INITIALIZE = "use_none";
  private static final String INIT_JAVA_ART = "use_platform_libs";
  private static final String FUZZ_DIR = "/data/fuzz/";
  private static final String PLATFORM_LIB_DIRS = ":/system/lib64/:/apex/com.android.i18n@1/lib64/";

  static {
    if (IS_ANDROID) {
      RulesJni.loadLibrary("jazzer_android_tooling", "/com/code_intelligence/jazzer/driver");
    }
  }

  public static void initialize() {
    if (!IS_ANDROID) {
      return;
    }

    String androidInitOptions = Opt.androidInitOptions.get();
    if (androidInitOptions == null) {
      return;
    }

    switch (androidInitOptions) {
      case INIT_JAVA_ART:
        registerNatives();
        break;

      case DO_NOT_INITIALIZE:
      case "":
        Log.warn("Android Runtime (ART) is not being initialized for this fuzzer.");
        break;

      default:
        Log.error(
            String.format(
                "%s is not a valid options for android_init_options. Valid Options: [use_none,"
                    + " use_platform_libs]",
                androidInitOptions));
        System.exit(1);
    }
  }
  ;

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
   *
   * @return The string for LD_LIBRARY_PATH.
   */
  public static String getLdLibraryPath() {
    String ldLibraryPath = FUZZ_DIR;

    String initOptString = Opt.androidInitOptions.get();
    if (initOptString != null && initOptString.equals(INIT_JAVA_ART)) {
      ldLibraryPath += PLATFORM_LIB_DIRS;
    }

    return ldLibraryPath;
  }

  private static native int registerNatives();
}
