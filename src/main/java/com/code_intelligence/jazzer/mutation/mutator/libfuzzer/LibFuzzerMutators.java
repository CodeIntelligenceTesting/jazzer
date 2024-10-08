/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.libfuzzer;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.util.stream.Stream;

public final class LibFuzzerMutators {
  private LibFuzzerMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    return Stream.of(new FuzzedDataProviderMutatorFactory());
  }
}
