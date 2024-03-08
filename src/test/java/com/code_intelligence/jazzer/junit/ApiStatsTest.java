/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ApiStatsTest {

  @Test
  void addNoStat() {
    ApiStats apiStats = new ApiStatsInterval();

    String expected = "==API STATS==" + " {\"endpoints\":[]}";
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
