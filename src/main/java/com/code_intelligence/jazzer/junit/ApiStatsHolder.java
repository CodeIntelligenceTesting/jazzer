/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import com.code_intelligence.jazzer.utils.Log;

public final class ApiStatsHolder {

  public static ApiStats apiStats = new ApiStatsNoop();

  public static void printApiStats() {
    Log.println(apiStats.stringify());
  }

  public static void collectApiStats(String requestURI, String method, int statusCode) {
    apiStats.addStat(requestURI, method, statusCode);
  }

  private ApiStatsHolder() {}
}
