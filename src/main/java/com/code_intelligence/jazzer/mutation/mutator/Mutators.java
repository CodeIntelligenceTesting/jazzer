/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.mutator;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.engine.IdentityCache;
import com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregateMutators;
import com.code_intelligence.jazzer.mutation.mutator.aggregate.SuperBuilderMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutators;
import com.code_intelligence.jazzer.mutation.mutator.proto.ProtoMutators;
import com.code_intelligence.jazzer.mutation.mutator.time.TimeMutators;
import java.util.stream.Stream;

public final class Mutators {
  private Mutators() {}

  public static ExtendedMutatorFactory newFactory() {
    return ChainedMutatorFactory.of(
        new IdentityCache(),
        NonNullableMutators.newFactories(),
        LangMutators.newFactories(),
        CollectionMutators.newFactories(),
        ProtoMutators.newFactories(),
        LibFuzzerMutators.newFactories(),
        TimeMutators.newFactories(),
        // Keep generic aggregate mutators last in case a concrete type is also an aggregate type.
        AggregateMutators.newFactories());
  }

  // Mutators for which the NullableMutatorFactory
  // shall not be applied
  public static class NonNullableMutators {
    public static Stream<MutatorFactory> newFactories() {
      return Stream.of(new SuperBuilderMutatorFactory());
    }
  }
}
