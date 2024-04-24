/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.engine.IdentityCache;
import com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregateMutators;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutators;
import com.code_intelligence.jazzer.mutation.mutator.proto.ProtoMutators;
import com.code_intelligence.jazzer.mutation.mutator.time.TimeMutators;

public final class Mutators {
  private Mutators() {}

  public static ExtendedMutatorFactory newFactory() {
    return ChainedMutatorFactory.of(
        new IdentityCache(),
        LangMutators.newFactories(),
        CollectionMutators.newFactories(),
        ProtoMutators.newFactories(),
        LibFuzzerMutators.newFactories(),
        AggregateMutators.newFactories(),
        TimeMutators.newFactories());
  }
}
