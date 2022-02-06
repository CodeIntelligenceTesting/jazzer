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

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Represents the Java view on a libFuzzer 8 bit counter coverage map.
 * By using a direct ByteBuffer, the counter array is shared directly with
 * native code.
 */
final public class CoverageMap {
  public static ByteBuffer counters = ByteBuffer.allocateDirect(0);

  // Called via reflection.
  @SuppressWarnings("unused")
  public static void enlargeIfNeeded(int nextId) {
    if (nextId >= counters.capacity()) {
      registerNewCoverageCounters();
      System.out.println("INFO: New number of inline 8-bit counters: " + counters.capacity());
    }
  }

  public static Set<Integer> getCoveredIds() {
    Set<Integer> coveredIds = new HashSet<>();
    for (int id = 0; id < counters.capacity(); id++) {
      if (counters.get(id) > 0) {
        coveredIds.add(id);
      }
    }
    return Collections.unmodifiableSet(coveredIds);
  }

  public static void replayCoveredIds(Set<Integer> coveredIds) {
    for (int id : coveredIds) {
      counters.put(id, (byte) 1);
    }
  }

  private static native void registerNewCoverageCounters();
}
