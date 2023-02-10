/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest()
public class JunitSpringWebApplicationTests {
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
    mockMvc.perform(get("/hello").param("name", "Maven"));
  }

  @Test
  public void unitTestShouldFail() throws Exception {
    mockMvc.perform(get("/buggy-hello").param("name", "error"));
  }

  @FuzzTest(maxDuration = "10s")
  public void fuzzTestShouldPass(FuzzedDataProvider data) throws Exception {
    if (!beforeCalled) {
      throw new RuntimeException("BeforeEach was not called");
    }

    String name = data.consumeRemainingAsString();
    mockMvc.perform(get("/hello").param("name", name));
  }

  @FuzzTest(maxDuration = "10s")
  public void fuzzTestShouldFail(FuzzedDataProvider data) throws Exception {
    if (!beforeCalled) {
      throw new RuntimeException("BeforeEach was not called");
    }

    String name = data.consumeRemainingAsString();
    mockMvc.perform(get("/buggy-hello").param("name", name));
  }
}
