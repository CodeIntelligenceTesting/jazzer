// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.junit;

import static com.code_intelligence.jazzer.junit.JazzerFuzzTestExecutor.durationStringToSeconds;
import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;

public class JazzerFuzzTestExecutorTest {
  @Test
  public void testDurationStringToSeconds() {
    assertThat(durationStringToSeconds("1m")).isEqualTo(60);
    assertThat(durationStringToSeconds("1min")).isEqualTo(60);
    assertThat(durationStringToSeconds("1h")).isEqualTo(60 * 60);
    assertThat(durationStringToSeconds("1h   2m 30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
    assertThat(durationStringToSeconds("1h2m30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
  }
}
