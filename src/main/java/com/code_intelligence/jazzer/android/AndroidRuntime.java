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

import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.utils.Log;
import com.github.fmeum.rules_jni.RulesJni;
import java.io.UnsupportedEncodingException;

/**
 * Loads Android tooling library and registers native functions.
 */
public class AndroidRuntime {
  private static final String doNotInitialize = "use_none";

  public static void initialize(String runtimeLibs) throws UnsupportedEncodingException {
    if (runtimeLibs == null) {
      return;
    }

    if (Opt.isAndroid) {
      try {
        System.loadLibrary("android_servers");
      } catch (Exception e) {
        Log.warn("Unable to load android_servers. If you are attempting to fuzz the system server "
            + ", check static_libs definition.");
      }
      RulesJni.loadLibrary("jazzer_android_tooling", "/com/code_intelligence/jazzer/driver");
      if (!runtimeLibs.equals(doNotInitialize)) {
        registerNatives();
      } else {
        Log.warn("Android Runtime (ART) is not being initialized for this fuzzer.");
      }
    }
  };

  /**
   * Returns a command to set the classpath for fuzzing.
   *
   * @return The classpath command.
   */
  public static String getClassPathsCommand() {
    String template = "export CLASSPATH=%s";
    return String.format(template, System.getProperty("java.class.path"));
  }

  private static native int registerNatives();
}