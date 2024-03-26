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
import org.springframework.http.HttpStatus;
import org.springframework.test.util.AssertionErrors;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.ResultMatcher;

public final class SpringFuzzTestHelper {
  public static ApiStats apiStats = new ApiStatsNoop();

  public static ResultMatcher statusIsNot5xxServerError() {
    return result -> {
      AssertionErrors.assertNotEquals(
          "Range for response status value " + result.getResponse().getStatus(),
          HttpStatus.Series.SERVER_ERROR,
          HttpStatus.Series.resolve(result.getResponse().getStatus()));
    };
  }

  public static ResultHandler collectApiStats(String requestURI) {
    return result -> {
      apiStats.addStat(
          requestURI, result.getRequest().getMethod(), result.getResponse().getStatus());
    };
  }

  public static void printApiStats() {
    Log.println(apiStats.stringify());
  }
}
