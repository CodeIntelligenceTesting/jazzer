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

import static com.code_intelligence.jazzer.junit.FuzzerDictionary.escapeForDictionary;
import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

class FuzzerDictionaryTest {
  @Test
  void testEscapeForDictionary() {
    assertThat(escapeForDictionary("foo")).isEqualTo("\"foo\"");
    assertThat(escapeForDictionary("f\"o\\o\tbar")).isEqualTo("\"f\\\"o\\\\o\tbar\"");
    assertThat(escapeForDictionary("\u0012\u001A")).isEqualTo("\"\\x12\\x1A\"");
    assertThat(escapeForDictionary("✂\uD83D\uDCCB"))
        .isEqualTo("\"\\xE2\\x9C\\x82\\xF0\\x9F\\x93\\x8B\"");
  }
}
