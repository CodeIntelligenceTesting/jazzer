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

package com.code_intelligence.jazzer.api;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

public class MinimizeTest {

  @Test
  public void testBasicRangeMapping() {
    // value=50 in [0, 100] with 1024 counters
    // offset = (100 - 50) / 100 * 1023 = 511
    Jazzer.minimize(50, 0, 100, 1024, 600000);
  }

  @Test
  public void testValueAtMinimum() {
    // value == minValue → offset = effectiveCounters - 1 (maximum signal)
    Jazzer.minimize(0, 0, 100, 1024, 600001);
  }

  @Test
  public void testValueAtMaximum() {
    // value == maxValue → offset = 0 (minimum signal)
    Jazzer.minimize(100, 0, 100, 1024, 600002);
  }

  @Test
  public void testValueAboveMaximum() {
    // value > maxValue → no signal (should not throw)
    Jazzer.minimize(200, 0, 100, 1024, 600003);
  }

  @Test
  public void testValueBelowMinimum() {
    // value < minValue → clamped to minValue (offset = effectiveCounters - 1)
    Jazzer.minimize(-10, 0, 100, 1024, 600004);
  }

  @Test
  public void testNegativeRange() {
    // Range with negative values: [-100, -50]
    Jazzer.minimize(-75, -100, -50, 1024, 600005);
  }

  @Test
  public void testSingleValueRange() {
    // minValue == maxValue → offset is always 0
    Jazzer.minimize(42, 42, 42, 1024, 600006);
  }

  @Test
  public void testLargeRange() {
    // Long.MIN_VALUE to Long.MAX_VALUE — should not overflow
    Jazzer.minimize(0, Long.MIN_VALUE, Long.MAX_VALUE, 1024, 600007);
  }

  @Test
  public void testCustomNumCounters() {
    // Expert overload with small counter count
    Jazzer.minimize(50, 0, 100, 10, 600008);
  }

  @Test
  public void testZeroNumCountersThrows() {
    try {
      Jazzer.minimize(50, 0, 100, 0, 600009);
      fail("Expected JazzerApiException for zero numCounters");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }
  }

  @Test
  public void testNegativeNumCountersThrows() {
    try {
      Jazzer.minimize(50, 0, 100, -5, 600010);
      fail("Expected JazzerApiException for negative numCounters");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }
  }

  @Test
  public void testMaxValueLessThanMinValueThrows() {
    try {
      Jazzer.minimize(50, 100, 0, 1024, 600011);
      fail("Expected JazzerApiException for maxValue < minValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must not be less than"));
    }
  }

  @Test
  public void testMultipleCallsSameId() {
    // Multiple calls with the same id should succeed (idempotent allocation)
    Jazzer.minimize(10, 0, 100, 1024, 600012);
    Jazzer.minimize(50, 0, 100, 1024, 600012);
    Jazzer.minimize(90, 0, 100, 1024, 600012);
  }

  @Test
  public void testDifferentIdsWithDifferentRanges() {
    Jazzer.minimize(50, 0, 100, 1024, 600013);
    Jazzer.minimize(500, 0, 1000, 512, 600014);
  }

  @Test
  public void testInconsistentNumCountersThrows() {
    // Same id and range but different numCounters (where range doesn't cap)
    Jazzer.minimize(50, 0, 10000, 1024, 600017);
    try {
      Jazzer.minimize(50, 0, 10000, 2048, 600017);
      fail("Expected JazzerApiException for inconsistent numCounters");
    } catch (JazzerApiException e) {
      assertTrue(
          e.getMessage().contains("numCounters")
              && e.getMessage().contains("must remain constant"));
    }
  }

  @Test
  public void testInconsistentMinValueThrows() {
    Jazzer.minimize(50, 0, 100, 1024, 600015);
    try {
      Jazzer.minimize(50, 10, 100, 1024, 600015);
      fail("Expected JazzerApiException for inconsistent minValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must remain constant"));
    }
  }

  @Test
  public void testInconsistentMaxValueThrows() {
    Jazzer.minimize(50, 0, 100, 1024, 600016);
    try {
      Jazzer.minimize(50, 0, 200, 1024, 600016);
      fail("Expected JazzerApiException for inconsistent maxValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must remain constant"));
    }
  }
}
