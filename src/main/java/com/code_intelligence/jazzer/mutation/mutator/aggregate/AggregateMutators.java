package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;

import java.util.ArrayList;
import java.util.List;

public final class AggregateMutators {
  private AggregateMutators() {}

  public static MutatorFactory newFactory() {
    List<MutatorFactory> factories = new ArrayList<>();

    try {
      Class.forName("java.lang.Record");
      factories.add(new RecordMutatorFactory());
    } catch (ClassNotFoundException ignored) {
    }

    return new ChainedMutatorFactory(factories.toArray(MutatorFactory[]::new));
  }
}
