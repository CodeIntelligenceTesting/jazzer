/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.time;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutate;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class ZonedDateTimeMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories(), TimeMutators.newFactories());
  }

  @AfterEach
  void cleanMockSize() {
    System.clearProperty(LibFuzzerMutate.MOCK_SIZE_KEY);
  }

  @Test
  void testZonedDateTimeMutator() {
    SerializingMutator<ZonedDateTime> mutator =
        (SerializingMutator<ZonedDateTime>)
            factory.createOrThrow(new TypeHolder<@NotNull ZonedDateTime>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("ZonedDateTime");

    PseudoRandom prng = anyPseudoRandom();

    ZonedDateTime inited = mutator.init(prng);
    assertThat(inited).isNotNull();

    ZonedDateTime mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }
}
