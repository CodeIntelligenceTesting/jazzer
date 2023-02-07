/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import org.junit.jupiter.api.Test;

class MessageMutatorTest {
  private static final MutatorFactory FACTORY =
      new ChainedMutatorFactory(LangMutators.FACTORY, ProtoMutators.FACTORY);

  @Test
  void testSimpleMessage() {
    SerializingMutator<PrimitiveField3> mutator = FACTORY.createOrThrow(PrimitiveField3.class);

    PrimitiveField3 msg;

    try (MockPseudoRandom prng = mockPseudoRandom(
             // not null
             1,
             // boolean
             false)) {
      msg = mutator.init(prng);
      assertThat(msg).isEqualTo(PrimitiveField3.getDefaultInstance());
    }

    try (MockPseudoRandom prng = mockPseudoRandom(
             // not null,
             1,
             // mutate first field
             0)) {
      msg = mutator.mutate(msg, prng);
      assertThat(msg).isNotEqualTo(PrimitiveField3.getDefaultInstance());
    }
  }
}
