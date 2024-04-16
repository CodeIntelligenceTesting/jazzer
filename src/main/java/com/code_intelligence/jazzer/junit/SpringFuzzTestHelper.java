/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import org.springframework.http.HttpStatus;
import org.springframework.test.util.AssertionErrors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

public final class SpringFuzzTestHelper {

  // We use 500 as a generic error status code, when an unexpected condition was encountered and no
  // more specific message is suitable. The "real/actual" status code by the application might be
  // different.
  private static final int API_ERROR_STATUS_CODE = 500;

  public static ResultMatcher statusIsNot5xxServerError() {
    return result -> {
      AssertionErrors.assertNotEquals(
          "Range for response status value " + result.getResponse().getStatus(),
          HttpStatus.Series.SERVER_ERROR,
          HttpStatus.Series.resolve(result.getResponse().getStatus()));
    };
  }

  public static ResultActions apiTest(
      MockMvc mockMvc, String requestURI, MockHttpServletRequestBuilder requestBuilder)
      throws Exception {
    String method =
        requestBuilder.buildRequest(mockMvc.getDispatcherServlet().getServletContext()).getMethod();
    try {
      return mockMvc.perform(requestBuilder).andDo(collectApiStats(requestURI));
    } catch (Exception e) {
      ApiStatsHolder.collectApiStats(requestURI, method, API_ERROR_STATUS_CODE);
      throw e;
    }
  }

  public static ResultHandler collectApiStats(String requestURI) {
    return result ->
        ApiStatsHolder.collectApiStats(
            requestURI, result.getRequest().getMethod(), result.getResponse().getStatus());
  }
}
