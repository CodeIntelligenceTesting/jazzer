/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static com.code_intelligence.jazzer.junit.SpringFuzzTestHelper.apiTest;
import static com.code_intelligence.jazzer.junit.SpringFuzzTestHelper.statusIsNot5xxServerError;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.example.JunitSpringWebApplication.HelloRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
public class JunitSpringWebApplicationTests {
  private static final ObjectMapper mapper = new ObjectMapper();

  @Autowired private MockMvc mockMvc;
  private boolean beforeCalled = false;

  @BeforeEach
  public void beforeEach() {
    beforeCalled = true;
  }

  @AfterEach
  public void afterEach() {
    beforeCalled = false;
  }

  @Test
  public void unitTestShouldPass() throws Exception {
    apiTest(mockMvc, "/hello", get("/hello").param("name", "Maven"));
  }

  @Test
  public void unitTestShouldFail() throws Exception {
    apiTest(mockMvc, "/buggy-hello", get("/buggy-hello").param("name", "error"));
  }

  @FuzzTest(maxDuration = "10s")
  public void fuzzTestShouldPass(FuzzedDataProvider data) throws Exception {
    if (!beforeCalled) {
      throw new RuntimeException("BeforeEach was not called");
    }

    String name = data.consumeRemainingAsString();
    apiTest(mockMvc, "/hello", get("/hello").param("name", name));
  }

  @FuzzTest(maxDuration = "10s")
  public void fuzzTestShouldFail(FuzzedDataProvider data) throws Exception {
    if (!beforeCalled) {
      throw new RuntimeException("BeforeEach was not called");
    }

    String name = data.consumeRemainingAsString();
    apiTest(mockMvc, "/buggy-hello", get("/buggy-hello").param("name", name))
        .andExpect(content().string(containsString(name)));
  }

  @FuzzTest(maxDuration = "10s")
  public void fuzzTestWithDtoShouldFail(HelloRequest helloRequest) throws Exception {
    if (!beforeCalled) {
      throw new RuntimeException("BeforeEach was not called");
    }
    Assumptions.assumeTrue(
        helloRequest != null && helloRequest.name != null && !helloRequest.name.isBlank());

    apiTest(
            mockMvc,
            "/hello",
            post("/hello")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(helloRequest)))
        .andExpect(content().string(containsString(helloRequest.name)))
        .andExpect(statusIsNot5xxServerError());
  }
}
