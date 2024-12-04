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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.createOrThrow;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto2.ExtendedMessage2;
import com.code_intelligence.jazzer.protobuf.Proto2.ExtendedSubmessage2;
import com.code_intelligence.jazzer.protobuf.Proto2.OriginalMessage2;
import com.code_intelligence.jazzer.protobuf.Proto2.OriginalSubmessage2;
import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MessageMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory =
        ChainedMutatorFactory.of(
            LangMutators.newFactories(),
            CollectionMutators.newFactories(),
            ProtoMutators.newFactories());
  }

  @Test
  void testSimpleMessage() {
    SerializingMutator<PrimitiveField3> mutator =
        createOrThrow(factory, new TypeHolder<PrimitiveField3>() {});

    PrimitiveField3 msg;

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // not null
            false,
            // boolean
            false)) {
      msg = mutator.init(prng);
      assertThat(msg).isEqualTo(PrimitiveField3.getDefaultInstance());
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // not null,
            false,
            // mutate first field
            0)) {
      msg = mutator.mutate(msg, prng);
      assertThat(msg).isNotEqualTo(PrimitiveField3.getDefaultInstance());
    }
  }

  @Test
  void testIncompleteMessageWithRequiredFields() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    OriginalMessage2.newBuilder()
        .setMessageField(OriginalSubmessage2.newBuilder().setNumericField(42).build())
        .setBoolField(true)
        .build()
        .writeTo(out);
    byte[] bytes = out.toByteArray();

    SerializingMutator<ExtendedMessage2> mutator =
        (SerializingMutator<ExtendedMessage2>)
            factory.createOrThrow(new TypeHolder<@NotNull ExtendedMessage2>() {}.annotatedType());
    ExtendedMessage2 extendedMessage = mutator.readExclusive(new ByteArrayInputStream(bytes));
    assertThat(extendedMessage)
        .isEqualTo(
            ExtendedMessage2.newBuilder()
                .setMessageField(
                    ExtendedSubmessage2.newBuilder()
                        .setNumericField(42)
                        .setMessageField(
                            OriginalSubmessage2.newBuilder().setNumericField(0).build()))
                .setBoolField(true)
                .setFloatField(0)
                .build());
  }
}
