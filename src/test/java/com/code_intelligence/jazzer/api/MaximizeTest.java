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

import org.junit.Test;

public class MaximizeTest {

  @Test
  public void testMaximizeBasic() {
    // Basic usage - should not throw
    Jazzer.maximize(50, 5000, 0, 100);
  }

  @Test
  public void testMaximizeWithMinValue() {
    // Value at minimum
    Jazzer.maximize(0, 5001, 0, 100);
  }

  @Test
  public void testMaximizeWithMaxValue() {
    // Value at maximum
    Jazzer.maximize(100, 5002, 0, 100);
  }

  @Test
  public void testMaximizeBelowMinValue() {
    // Value below minimum - should be a no-op (no signal)
    Jazzer.maximize(-10, 5003, 0, 100);
  }

  @Test
  public void testMaximizeAboveMaxValue() {
    // Value above maximum - should be clamped
    Jazzer.maximize(200, 5004, 0, 100);
  }

  @Test
  public void testMaximizeNegativeRange() {
    // Negative range
    Jazzer.maximize(-50, 5005, -100, 0);
  }

  @Test
  public void testMaximizeSingleValueRange() {
    // Range with single value
    Jazzer.maximize(42, 5006, 42, 42);
  }

  @Test(expected = JazzerApiException.class)
  public void testMaximizeInvalidRange() {
    // maxValue < minValue - should throw JazzerApiException
    Jazzer.maximize(50, 5007, 100, 0);
  }

  @Test
  public void testMaximizeSameRangeSucceeds() {
    // Multiple calls with same id and range should succeed
    Jazzer.maximize(25, 5009, 0, 100);
    Jazzer.maximize(50, 5009, 0, 100);
    Jazzer.maximize(75, 5009, 0, 100);
  }

  @Test(expected = JazzerApiException.class)
  public void testMaximizeLargeRange() {
    // Extremely large range - should throw JazzerApiException
    Jazzer.maximize(0, 5010, Long.MIN_VALUE, Long.MAX_VALUE);
  }

  @Test
  public void testMaximizeDifferentIds() {
    // Different IDs can have different ranges
    Jazzer.maximize(50, 5011, 0, 100);
    Jazzer.maximize(500, 5012, 0, 1000);
    Jazzer.maximize(-5, 5013, -10, 10);
  }
}
