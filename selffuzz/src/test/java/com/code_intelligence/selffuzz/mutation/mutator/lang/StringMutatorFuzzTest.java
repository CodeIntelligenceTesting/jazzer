/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.selffuzz.mutation.mutator.lang;

import static com.code_intelligence.selffuzz.Helpers.assertMutator;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import java.io.IOException;

@SuppressWarnings("unchecked")
class StringMutatorFuzzTest {
  @FuzzTest(maxDuration = "10m")
  void stringMutatorTest(long seed, byte @NotNull [] data) throws IOException {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            Mutators.newFactory().createOrThrow(new TypeHolder<String>() {}.annotatedType());
    assertMutator(mutator, data, seed);
  }
}
