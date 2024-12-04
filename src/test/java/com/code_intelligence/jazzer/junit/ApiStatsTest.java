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

package com.code_intelligence.jazzer.junit;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ApiStatsTest {

  @Test
  void addNoStat() {
    ApiStats apiStats = new ApiStatsInterval();

    String expected = ApiStatsInterval.NO_STATS;
    assertEquals(expected, apiStats.stringify());
  }

  @Test
  void addSingleStat() {
    ApiStats apiStats = new ApiStatsInterval();
    apiStats.addStat("https://example.com", "GET", 200);

    String expected =
        "==API STATS=="
            + " {\"endpoints\":[{\"method\":\"GET\",\"URL\":\"https://example.com\",\"statusCodes\":{\"200\":1}}]}";
    assertEquals(expected, apiStats.stringify());
  }

  @Test
  void addMultipleStats() {
    ApiStats apiStats = new ApiStatsInterval();
    apiStats.addStat("https://example.com", "GET", 200);
    apiStats.addStat("https://example.com", "GET", 200);
    apiStats.addStat("https://example.com", "POST", 201);
    apiStats.addStat("https://example.org", "GET", 404);

    String expected =
        "==API STATS=="
            + " {\"endpoints\":[{\"method\":\"GET\",\"URL\":\"https://example.com\",\"statusCodes\":{\"200\":2}},{\"method\":\"GET\",\"URL\":\"https://example.org\",\"statusCodes\":{\"404\":1}},{\"method\":\"POST\",\"URL\":\"https://example.com\",\"statusCodes\":{\"201\":1}}]}";
    assertEquals(expected, apiStats.stringify());
  }
}
