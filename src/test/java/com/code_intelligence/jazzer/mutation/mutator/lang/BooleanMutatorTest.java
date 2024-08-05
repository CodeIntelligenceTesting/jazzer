/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class BooleanMutatorTest {
  @Test
  void testPrimitive() {
    SerializingMutator<Boolean> mutator = LangMutators.newFactory().createOrThrow(boolean.class);
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
            LangMutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull Boolean>() {}.annotatedType());
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
    SerializingMutator<Boolean> mutator = LangMutators.newFactory().createOrThrow(boolean.class);
    try (MockPseudoRandom prng = mockPseudoRandom(true, false)) {
      assertThat(mutator.crossOver(true, false, prng)).isTrue();
      assertThat(mutator.crossOver(true, false, prng)).isFalse();
    }
  }
}
