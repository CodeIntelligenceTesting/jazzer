/*
 * Copyright 2026 Code Intelligence GmbH
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
 * Registers per-edge source location metadata with the native symbolizer so that libFuzzer's {@code
 * -print_pcs}, {@code -print_funcs}, and {@code -print_coverage} flags show Java source locations
 * instead of meaningless hex addresses.
 *
 * <p>Called from the instrumentor after each class is instrumented. Thread-safe on the native side.
 */
public final class SourceLocationRegistry {
  static {
    RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
  }

  private SourceLocationRegistry() {}

  /**
   * Register source locations for a contiguous range of coverage edge IDs.
   *
   * @param sourceFile Qualified source path (e.g. "com/example/Foo.java")
   * @param methodNames Deduplicated method name table for this class
   * @param firstEdgeId Global ID of the first edge in this class
   * @param edgeData Flat array: [packedLine0, methodIdx0, packedLine1, methodIdx1, ...]. The sign
   *     bit of each packedLine encodes whether the edge is a function entry point.
   */
  public static native void registerLocations(
      String sourceFile, String[] methodNames, int firstEdgeId, int[] edgeData);
}
