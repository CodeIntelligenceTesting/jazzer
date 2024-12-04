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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TestSupport.ParameterHolder;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class BooleanMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  @Test
  void testPrimitive() {
    SerializingMutator<Boolean> mutator =
        (SerializingMutator<Boolean>)
            factory.createOrThrow(
                new ParameterHolder() {
                  void singleParam(boolean parameter) {}
                }.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Boolean");

    boolean bool;
    try (MockPseudoRandom prng = mockPseudoRandom(true)) {
      bool = mutator.init(prng);
    }
    assertThat(bool).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      bool = mutator.mutate(bool, prng);
    }
    assertThat(bool).isFalse();
  }

  @Test
  void testBoxed() {
    SerializingMutator<Boolean> mutator =
        (SerializingMutator<Boolean>)
            factory.createOrThrow(new TypeHolder<@NotNull Boolean>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Boolean");

    Boolean bool;
    try (MockPseudoRandom prng = mockPseudoRandom(false)) {
      bool = mutator.init(prng);
    }
    assertThat(bool).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      bool = mutator.mutate(bool, prng);
    }
    assertThat(bool).isTrue();
  }

  @Test
  void testCrossOver() {
    SerializingMutator<Boolean> mutator =
        (SerializingMutator<Boolean>)
            factory.createOrThrow(
                new ParameterHolder() {
                  void singleParam(boolean parameter) {}
                }.annotatedType());
    try (MockPseudoRandom prng = mockPseudoRandom(true, false)) {
      assertThat(mutator.crossOver(true, false, prng)).isTrue();
      assertThat(mutator.crossOver(true, false, prng)).isFalse();
    }
  }
}
