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
