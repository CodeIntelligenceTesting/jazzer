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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

public class MaximizeTest {

  @Test
  public void testBasicRangeMapping() {
    // value=50 in [0, 100] with 1024 counters → offset = 50/100 * 1023 = 511
    Jazzer.maximize(50, 0, 100, 1024, 500000);
  }

  @Test
  public void testValueAtMinimum() {
    // value == minValue → offset = 0
    Jazzer.maximize(0, 0, 100, 1024, 500001);
  }

  @Test
  public void testValueAtMaximum() {
    // value == maxValue → offset = numCounters - 1
    Jazzer.maximize(100, 0, 100, 1024, 500002);
  }

  @Test
  public void testValueBelowMinimum() {
    // value < minValue → no signal (should not throw)
    Jazzer.maximize(-10, 0, 100, 1024, 500003);
  }

  @Test
  public void testValueAboveMaximum() {
    // value > maxValue → clamped to maxValue (offset = numCounters - 1)
    Jazzer.maximize(200, 0, 100, 1024, 500004);
  }

  @Test
  public void testNegativeRange() {
    // Range with negative values: [-100, -50]
    Jazzer.maximize(-75, -100, -50, 1024, 500005);
  }

  @Test
  public void testSingleValueRange() {
    // minValue == maxValue → offset is always 0
    Jazzer.maximize(42, 42, 42, 1024, 500006);
  }

  @Test
  public void testLargeRange() {
    // Long.MIN_VALUE to Long.MAX_VALUE — should not overflow
    Jazzer.maximize(0, Long.MIN_VALUE, Long.MAX_VALUE, 1024, 500007);
  }

  @Test
  public void testCustomNumCounters() {
    // Expert overload with small counter count
    Jazzer.maximize(50, 0, 100, 10, 500008);
  }

  @Test
  public void testZeroNumCountersThrows() {
    try {
      Jazzer.maximize(50, 0, 100, 0, 500009);
      fail("Expected JazzerApiException for zero numCounters");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }
  }

  @Test
  public void testNegativeNumCountersThrows() {
    try {
      Jazzer.maximize(50, 0, 100, -5, 500010);
      fail("Expected JazzerApiException for negative numCounters");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }
  }

  @Test
  public void testMaxValueLessThanMinValueThrows() {
    try {
      Jazzer.maximize(50, 100, 0, 1024, 500011);
      fail("Expected JazzerApiException for maxValue < minValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must not be less than"));
    }
  }

  @Test
  public void testMultipleCallsSameId() {
    // Multiple calls with the same id should succeed (idempotent allocation)
    Jazzer.maximize(10, 0, 100, 1024, 500012);
    Jazzer.maximize(50, 0, 100, 1024, 500012);
    Jazzer.maximize(90, 0, 100, 1024, 500012);
  }

  @Test
  public void testDifferentIdsWithDifferentRanges() {
    Jazzer.maximize(50, 0, 100, 1024, 500013);
    Jazzer.maximize(500, 0, 1000, 512, 500014);
  }

  @Test
  public void testInconsistentNumCountersThrows() {
    // Same id and range but different numCounters (where range doesn't cap)
    Jazzer.maximize(50, 0, 10000, 1024, 500017);
    try {
      Jazzer.maximize(50, 0, 10000, 2048, 500017);
      fail("Expected JazzerApiException for inconsistent numCounters");
    } catch (JazzerApiException e) {
      assertTrue(
          e.getMessage().contains("numCounters")
              && e.getMessage().contains("must remain constant"));
    }
  }

  @Test
  public void testInconsistentMinValueThrows() {
    Jazzer.maximize(50, 0, 100, 1024, 500015);
    try {
      Jazzer.maximize(50, 10, 100, 1024, 500015);
      fail("Expected JazzerApiException for inconsistent minValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must remain constant"));
    }
  }

  @Test
  public void testInconsistentMaxValueThrows() {
    Jazzer.maximize(50, 0, 100, 1024, 500016);
    try {
      Jazzer.maximize(50, 0, 200, 1024, 500016);
      fail("Expected JazzerApiException for inconsistent maxValue");
    } catch (JazzerApiException e) {
      assertTrue(e.getMessage().contains("must remain constant"));
    }
  }

  @Test
  public void testDefaultNumCountersConstant() {
    assertEquals(1024, Jazzer.DEFAULT_NUM_COUNTERS);
  }
}
