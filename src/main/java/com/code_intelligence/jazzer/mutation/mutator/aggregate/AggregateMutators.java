package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.util.stream.Stream;

public final class AggregateMutators {
  private AggregateMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    Stream.Builder<MutatorFactory> factories = Stream.builder();

    try {
      Class.forName("java.lang.Record");
      factories.add(new RecordMutatorFactory());
    } catch (ClassNotFoundException ignored) {
    }

    return factories.build();
  }
}
