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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import sun.misc.Unsafe;

/**
 * Represents the Java view on a libFuzzer 8 bit counter coverage map. By using a direct ByteBuffer,
 * the counters are shared directly with native code.
 */
final public class CoverageMap {
  private static final String ENV_MAX_NUM_COUNTERS = "JAZZER_MAX_NUM_COUNTERS";

  private static final int MAX_NUM_COUNTERS = System.getenv(ENV_MAX_NUM_COUNTERS) != null
      ? Integer.parseInt(System.getenv(ENV_MAX_NUM_COUNTERS))
      : 1 << 20;

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();

  static {
    if (UNSAFE == null) {
      System.out.println("ERROR: Failed to get Unsafe instance for CoverageMap.%n"
          + "       Please file a bug at:%n"
          + "         https://github.com/CodeIntelligenceTesting/jazzer/issues/new");
      System.exit(1);
    }
  }

  /**
   * The collection of coverage counters directly interacted with by classes that are instrumented
   * for coverage. The instrumentation assumes that this is always one contiguous block of memory,
   * so it is allocated once at maximum size. Using a larger number here increases the memory usage
   * of all fuzz targets, but has otherwise no impact on performance.
   */
  public static final long countersAddress = UNSAFE.allocateMemory(MAX_NUM_COUNTERS);

  static {
    UNSAFE.setMemory(countersAddress, MAX_NUM_COUNTERS, (byte) 0);
    initialize(countersAddress);
  }

  private static final int INITIAL_NUM_COUNTERS = 1 << 9;

  static {
    registerNewCounters(0, INITIAL_NUM_COUNTERS);
  }

  /**
   * The number of coverage counters that are currently registered with libFuzzer. This number grows
   * dynamically as classes are instrumented and should be kept as low as possible as libFuzzer has
   * to iterate over the whole map for every execution.
   */
  private static int currentNumCounters = INITIAL_NUM_COUNTERS;

  // Called via reflection.
  @SuppressWarnings("unused")
  public static void enlargeIfNeeded(int nextId) {
    int newNumCounters = currentNumCounters;
    while (nextId >= newNumCounters) {
      newNumCounters = 2 * newNumCounters;
      if (newNumCounters > MAX_NUM_COUNTERS) {
        System.out.printf("ERROR: Maximum number (%s) of coverage counters exceeded. Try to%n"
                + "       limit the scope of a single fuzz target as much as possible to keep the%n"
                + "       fuzzer fast.%n"
                + "       If that is not possible, the maximum number of counters can be increased%n"
                + "       via the %s environment variable.",
            MAX_NUM_COUNTERS, ENV_MAX_NUM_COUNTERS);
        System.exit(1);
      }
    }
    if (newNumCounters > currentNumCounters) {
      registerNewCounters(currentNumCounters, newNumCounters);
      currentNumCounters = newNumCounters;
      System.out.println("INFO: New number of coverage counters: " + currentNumCounters);
    }
  }

  // Called by the coverage instrumentation.
  @SuppressWarnings("unused")
  public static void recordCoverage(final int id) {
    final long address = countersAddress + id;
    final byte counter = UNSAFE.getByte(address);
    UNSAFE.putByte(address, (byte) (counter == -1 ? 1 : counter + 1));
  }

  public static Set<Integer> getCoveredIds() {
    Set<Integer> coveredIds = new HashSet<>();
    for (int id = 0; id < currentNumCounters; id++) {
      if (UNSAFE.getByte(countersAddress + id) > 0) {
        coveredIds.add(id);
      }
    }
    return Collections.unmodifiableSet(coveredIds);
  }

  public static void replayCoveredIds(Set<Integer> coveredIds) {
    for (int id : coveredIds) {
      UNSAFE.putByte(countersAddress + id, (byte) 1);
    }
  }

  private static native void initialize(long countersAddress);

  private static native void registerNewCounters(int oldNumCounters, int newNumCounters);
}
