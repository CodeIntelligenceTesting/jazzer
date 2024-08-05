/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer;

import static com.code_intelligence.jazzer.Jazzer.isLibFuzzerOptionEnabled;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.asList;

import org.junit.jupiter.api.Test;

class JazzerTest {
  @Test
  void testIsLibFuzzerOptionEnabled() {
    assertThat(isLibFuzzerOptionEnabled("foo", asList("-bar=1", "--baz=0"))).isFalse();
    assertThat(isLibFuzzerOptionEnabled("foo", asList("-bar=1", "-foo=1", "baz"))).isTrue();
    assertThat(isLibFuzzerOptionEnabled("foo", asList("-bar=1", "-foo=1", "some/path", "-foo=")))
        .isFalse();
    assertThat(
            isLibFuzzerOptionEnabled(
                "foo", asList("-bar=1", "-foo=1", "-baz=1", "-foo=0", "--baz=0", "-foo=12")))
        .isTrue();
  }
}
