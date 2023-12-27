/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.lang.reflect.InvocationTargetException;
import java.util.stream.Stream;

public final class AggregateMutators {
  private AggregateMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    // Register the record mutator first as it is more specific.
    return Stream.concat(newRecordMutatorFactoryIfSupported(), Stream.of(new BeanMutatorFactory()));
  }

  private static Stream<MutatorFactory> newRecordMutatorFactoryIfSupported() {
    if (!supportsRecords()) {
      return Stream.empty();
    }
    try {
      // Instantiate RecordMutatorFactory via reflection as making it a compile time dependency
      // breaks the r8 step in the Android build.
      Class<? extends MutatorFactory> recordMutatorFactory;
      recordMutatorFactory =
          Class.forName(AggregateMutators.class.getPackage().getName() + ".RecordMutatorFactory")
              .asSubclass(MutatorFactory.class);
      return Stream.of(recordMutatorFactory.getDeclaredConstructor().newInstance());
    } catch (ClassNotFoundException
        | NoSuchMethodException
        | InstantiationException
        | IllegalAccessException
        | InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean supportsRecords() {
    try {
      Class.forName("java.lang.Record");
      return true;
    } catch (ClassNotFoundException ignored) {
      return false;
    }
  }
}
