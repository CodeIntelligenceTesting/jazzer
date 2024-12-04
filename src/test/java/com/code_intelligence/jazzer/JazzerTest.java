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
