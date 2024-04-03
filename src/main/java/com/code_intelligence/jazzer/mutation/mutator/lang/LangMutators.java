/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.lang;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.util.stream.Stream;

public final class LangMutators {
  private LangMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    return Stream.of(
        // DON'T EVER SORT THESE! The order is important for the mutator engine to work correctly.
        new NullableMutatorFactory(),
        new BooleanMutatorFactory(),
        new FloatingPointMutatorFactory(),
        new IntegralMutatorFactory(),
        new StringMutatorFactory(),
        new EnumMutatorFactory(),
        new InputStreamMutatorFactory(),
        new PrimitiveArrayMutatorFactory());
  }
}
