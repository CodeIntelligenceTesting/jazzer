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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.github.fmeum.rules_jni.RulesJni;

public class NativeValueProfileFuzzer {
  public static void fuzzerInitialize() {
    RulesJni.loadLibrary("native_value_profile_fuzzer", NativeValueProfileFuzzer.class);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    long[] blocks = data.consumeLongs(2);
    if (blocks.length != 2) return;
    if (checkAccess(blocks[0], blocks[1])) {
      throw new FuzzerSecurityIssueLow("Security breached");
    }
  }

  private static native boolean checkAccess(long block1, long block2);
}
