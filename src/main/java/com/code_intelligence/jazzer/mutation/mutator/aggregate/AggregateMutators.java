/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

public final class AggregateMutators {
  private AggregateMutators() {}

  public static MutatorFactory newFactory() {
    List<MutatorFactory> factories = new ArrayList<>();
    if (supportsRecords()) {
      try {
        // Instantiate RecordMutatorFactory via reflection as making it a compile time dependency
        // breaks the r8 step in the Android build.
        Class<? extends MutatorFactory> recordMutatorFactory;
        recordMutatorFactory =
            Class.forName(AggregateMutators.class.getPackage().getName() + ".RecordMutatorFactory")
                .asSubclass(MutatorFactory.class);
        factories.add(recordMutatorFactory.getDeclaredConstructor().newInstance());
      } catch (ClassNotFoundException
          | NoSuchMethodException
          | InstantiationException
          | IllegalAccessException
          | InvocationTargetException e) {
        throw new IllegalStateException(e);
      }
    }
    return new ChainedMutatorFactory(factories.toArray(new MutatorFactory[0]));
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
