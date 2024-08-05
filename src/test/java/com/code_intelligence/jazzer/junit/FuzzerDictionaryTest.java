/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
