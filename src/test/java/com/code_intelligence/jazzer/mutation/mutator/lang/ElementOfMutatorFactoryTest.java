/*
 * Copyright 2025 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.mutation.annotation.ElementOf;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class ElementOfMutatorFactoryTest {
  private ChainedMutatorFactory factory;

  @BeforeEach
  void setUp() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  @Test
  void usesProvidedIntegers() {
    SerializingMutator<Integer> mutator =
        (SerializingMutator<Integer>)
            factory.createOrThrow(
                new TypeHolder<
                    @ElementOf(integers = {1, 2, 3}) @NotNull Integer>() {}.annotatedType());

    int value;
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      value = mutator.init(prng);
    }
    assertThat(value).isEqualTo(1);

    try (MockPseudoRandom prng = mockPseudoRandom(2)) {
      value = mutator.mutate(value, prng);
    }
    assertThat(value).isEqualTo(3);
  }

  @Test
  void usesProvidedStrings() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<
                    @ElementOf(strings = {"one", "two"}) @NotNull String>() {}.annotatedType());

    String value;
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      value = mutator.init(prng);
    }
    assertThat(value).isEqualTo("one");

    try (MockPseudoRandom prng = mockPseudoRandom(1)) {
      value = mutator.mutate(value, prng);
    }
    assertThat(value).isEqualTo("two");
  }

  @Test
  void rejectsEmptyArrayForMatchingType() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            factory.createOrThrow(
                new TypeHolder<@ElementOf(bytes = {0, 1, 2}) Integer>() {}.annotatedType()));
  }
}
