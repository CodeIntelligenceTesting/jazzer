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

import com.code_intelligence.jazzer.utils.UnsafeProvider;
import com.github.fmeum.rules_jni.RulesJni;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import sun.misc.Unsafe;

/**
 * Generic foundation for mapping program state to coverage counters.
 *
 * <p>This class provides a flexible API for any consumer wanting to translate program state signals
 * to coverage counters, enabling incremental progress feedback to the fuzzer. Use cases include:
 *
 * <ul>
 *   <li>Hill-climbing (maximize API)
 *   <li>State exploration
 *   <li>Custom progress signals
 * </ul>
 *
 * <p>Each counter is a byte (0-255). Each ID has a range of counters accessible via indexes [0,
 * numCounters - 1]. Allocation is explicit - call {@link #ensureCountersAllocated} first, then use
 * the set methods.
 *
 * <p>The counters are allocated from a dedicated memory region separate from the main coverage map,
 * ensuring isolation and preventing interference with regular coverage tracking.
 */
public final class ExtraCountersTracker {
  static {
    RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
  }

  private static final String ENV_MAX_COUNTERS = "JAZZER_EXTRA_COUNTERS_MAX";

  private static final int DEFAULT_MAX_COUNTERS = 1 << 18;

  /** Maximum number of counters available (default 256K, configurable via environment variable). */
  private static final int MAX_COUNTERS = initMaxCounters();

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();

  /** Base address of the counter memory region. */
  private static final long countersAddress = UNSAFE.allocateMemory(MAX_COUNTERS);

  /** Map from ID to allocated counter range. */
  private static final ConcurrentHashMap<Integer, CounterRange> idToRange =
      new ConcurrentHashMap<>();

  /** Next available offset for counter allocation. */
  private static final AtomicInteger nextOffset = new AtomicInteger(0);

  static {
    // Zero-initialize the counter region
    UNSAFE.setMemory(countersAddress, MAX_COUNTERS, (byte) 0);
    // Initialize native side (like CoverageMap does)
    initialize(countersAddress);
  }

  private ExtraCountersTracker() {}

  /**
   * Allocates a range of counters for the given ID.
   *
   * <p>Idempotent: if already allocated, validates that numCounters matches.
   *
   * @param id Unique identifier for this counter range
   * @param numCounters Number of counters to allocate
   * @throws IllegalArgumentException if called with different numCounters for same ID
   * @throws IllegalStateException if counter space is exhausted
   */
  public static void ensureCountersAllocated(int id, int numCounters) {
    if (numCounters <= 0) {
      throw new IllegalArgumentException("numCounters must be positive, got: " + numCounters);
    }

    CounterRange range =
        idToRange.computeIfAbsent(
            id,
            key -> {
              int startOffset = nextOffset.getAndAdd(numCounters);
              if (startOffset > MAX_COUNTERS - numCounters) {
                throw new IllegalStateException(
                    String.format(
                        "Counter space exhausted: requested %d counters at offset %d, "
                            + "but only %d total counters available. "
                            + "Increase via %s environment variable or use smaller ranges.",
                        numCounters, startOffset, MAX_COUNTERS, ENV_MAX_COUNTERS));
              }
              int endOffset = startOffset + numCounters;

              CounterRange newRange = new CounterRange(startOffset, numCounters);

              // Register the new counters with libFuzzer
              registerCounters(startOffset, endOffset);

              return newRange;
            });

    // Validate numCounters matches (for calls with same ID but different numCounters)
    if (range.numCounters != numCounters) {
      throw new IllegalArgumentException(
          String.format(
              "numCounters for id %d must remain constant. Expected %d, got %d.",
              id, range.numCounters, numCounters));
    }
  }

  /**
   * Helper to get range for an allocated ID, throws if not allocated.
   *
   * @param id The ID to look up
   * @return The CounterRange for this ID
   * @throws IllegalStateException if no counters allocated for this ID
   */
  private static CounterRange getRange(int id) {
    CounterRange range = idToRange.get(id);
    if (range == null) {
      throw new IllegalStateException("No counters allocated for id: " + id);
    }
    return range;
  }

  /**
   * Sets the value of a specific counter within a range.
   *
   * @param id The ID of the allocated counter range
   * @param offset Offset within the range [0, numCounters)
   * @param value The value to set (0-255)
   * @throws IllegalStateException if no counters allocated for this ID
   * @throws IndexOutOfBoundsException if offset is out of bounds
   */
  public static void setCounter(int id, int offset, byte value) {
    CounterRange range = getRange(id);
    if (offset < 0 || offset >= range.numCounters) {
      throw new IndexOutOfBoundsException(
          String.format(
              "Counter offset %d out of bounds for range with %d counters",
              offset, range.numCounters));
    }
    long address = countersAddress + range.startOffset + offset;
    UNSAFE.putByte(address, value);
  }

  /**
   * Sets the first counter (offset = 0) to the given value.
   *
   * @param id The ID of the allocated counter range
   * @param value The value to set (0-255)
   * @throws IllegalStateException if no counters allocated for this ID
   */
  public static void setCounter(int id, byte value) {
    setCounter(id, 0, value);
  }

  /**
   * Sets the first counter (offset = 0) to 1.
   *
   * @param id The ID of the allocated counter range
   * @throws IllegalStateException if no counters allocated for this ID
   */
  public static void setCounter(int id) {
    setCounter(id, 0, (byte) 1);
  }

  /**
   * Sets multiple consecutive counters to a value.
   *
   * <p>Efficient for setting ranges (e.g., all counters from 0 to N for hill-climbing).
   *
   * @param id The ID of the allocated counter range
   * @param fromOffset Start offset (inclusive)
   * @param toOffset End offset (inclusive)
   * @param value The value to set
   * @throws IllegalStateException if no counters allocated for this ID
   * @throws IndexOutOfBoundsException if offsets are out of bounds
   */
  public static void setCounterRange(int id, int fromOffset, int toOffset, byte value) {
    CounterRange range = getRange(id);
    if (fromOffset < 0) {
      throw new IndexOutOfBoundsException("fromOffset must be non-negative, got: " + fromOffset);
    }
    if (toOffset >= range.numCounters) {
      throw new IndexOutOfBoundsException(
          String.format(
              "toOffset %d out of bounds for range with %d counters", toOffset, range.numCounters));
    }
    if (fromOffset > toOffset) {
      throw new IllegalArgumentException(
          String.format(
              "fromOffset (%d) must not be greater than toOffset (%d)", fromOffset, toOffset));
    }

    long startAddress = countersAddress + range.startOffset + fromOffset;
    int length = toOffset - fromOffset + 1;
    UNSAFE.setMemory(startAddress, length, value);
  }

  /**
   * Sets counters from offset 0 to toOffset (inclusive) to the given value.
   *
   * @param id The ID of the allocated counter range
   * @param toOffset End offset (inclusive)
   * @param value The value to set
   * @throws IllegalStateException if no counters allocated for this ID
   * @throws IndexOutOfBoundsException if toOffset is out of bounds
   */
  public static void setCounterRange(int id, int toOffset, byte value) {
    setCounterRange(id, 0, toOffset, value);
  }

  /**
   * Sets counters from offset 0 to toOffset (inclusive) to 1.
   *
   * <p>Ideal for hill-climbing/maximize patterns where you want to signal progress up to a point.
   *
   * @param id The ID of the allocated counter range
   * @param toOffset End offset (inclusive)
   * @throws IllegalStateException if no counters allocated for this ID
   * @throws IndexOutOfBoundsException if toOffset is out of bounds
   */
  public static void setCounterRange(int id, int toOffset) {
    setCounterRange(id, 0, toOffset, (byte) 1);
  }

  /** Internal record of an allocated counter range. */
  private static final class CounterRange {
    final int startOffset;
    final int numCounters;

    CounterRange(int startOffset, int numCounters) {
      this.startOffset = startOffset;
      this.numCounters = numCounters;
    }
  }

  private static int initMaxCounters() {
    String value = System.getenv(ENV_MAX_COUNTERS);
    if (value == null || value.isEmpty()) {
      return DEFAULT_MAX_COUNTERS;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      if (parsed < 0) {
        throw new IllegalArgumentException(
            ENV_MAX_COUNTERS + " must not be negative, got: " + parsed);
      }
      return parsed;
    } catch (NumberFormatException e) {
      return DEFAULT_MAX_COUNTERS;
    }
  }

  // Native methods

  /**
   * Initializes the native counter tracker with the base address of the counter region.
   *
   * @param countersAddress The base address of the counter memory region
   */
  private static native void initialize(long countersAddress);

  /**
   * Registers a range of counters with libFuzzer.
   *
   * @param startOffset Start offset of the range to register
   * @param endOffset End offset (exclusive) of the range to register
   */
  private static native void registerCounters(int startOffset, int endOffset);
}
