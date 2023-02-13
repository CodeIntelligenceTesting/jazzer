/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.errorprone.annotations.Immutable;
import org.junit.jupiter.api.Test;

class EnumMutatorTest {
  enum TestEnumOne { A }

  enum TestEnum { A, B, C }

  @Test
  void testBoxed() {
    SerializingMutator<TestEnum> mutator =
        (SerializingMutator<TestEnum>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<@NotNull TestEnum>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Enum<TestEnum>");
    TestEnum cl;
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      cl = mutator.init(prng);
    }
    assertThat(cl).isEqualTo(TestEnum.A);

    try (MockPseudoRandom prng = mockPseudoRandom(1)) {
      cl = mutator.mutate(cl, prng);
    }
    assertThat(cl).isEqualTo(TestEnum.B);

    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      cl = mutator.mutate(cl, prng);
    }
    assertThat(cl).isEqualTo(TestEnum.A);

    try (MockPseudoRandom prng = mockPseudoRandom(2)) {
      cl = mutator.mutate(cl, prng);
    }
    assertThat(cl).isEqualTo(TestEnum.C);

    try (MockPseudoRandom prng = mockPseudoRandom(1)) {
      cl = mutator.mutate(cl, prng);
    }
    assertThat(cl).isEqualTo(TestEnum.B);
  }

  @Test
  void testEnumWithOneElementShouldThrow() {
    assertThrows(IllegalArgumentException.class, () -> {
      SerializingMutator<TestEnumOne> mutator =
          (SerializingMutator<TestEnumOne>) LangMutators.newFactory().createOrThrow(
              new TypeHolder<@NotNull TestEnumOne>() {}.annotatedType());
    }, "When trying to build mutators for Enum with one value, an Exception should be thrown.");
  }
}
