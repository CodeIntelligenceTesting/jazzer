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

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto3.OptionalPrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedPrimitiveField3;
import org.junit.jupiter.api.Test;

class BuilderMutatorProto3Test {
  private static final MutatorFactory FACTORY = new ChainedMutatorFactory(
      LangMutators.newFactory(), CollectionMutators.newFactory(), ProtoMutators.newFactory());

  @Test
  void testPrimitiveField() {
    InPlaceMutator<PrimitiveField3.Builder> mutator =
        (InPlaceMutator<PrimitiveField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<PrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Boolean}");

    PrimitiveField3.Builder builder = PrimitiveField3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(/* mutate first field */ 0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isFalse();
  }

  @Test
  void testOptionalPrimitiveField() {
    InPlaceMutator<OptionalPrimitiveField3.Builder> mutator =
        (InPlaceMutator<OptionalPrimitiveField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<OptionalPrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<Boolean>}");

    OptionalPrimitiveField3.Builder builder = OptionalPrimitiveField3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // present
             1,
             // boolean
             false)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // present
             1,
             // boolean
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate as non-null Boolean
             1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // not present
             0)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isFalse();
    assertThat(builder.getSomeField()).isFalse();
  }

  @Test
  void testRepeatedPrimitiveField() {
    InPlaceMutator<RepeatedPrimitiveField3.Builder> mutator =
        (InPlaceMutator<RepeatedPrimitiveField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RepeatedPrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<Boolean>}");

    RepeatedPrimitiveField3.Builder builder = RepeatedPrimitiveField3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // list size 1
             1,
             // boolean,
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true).inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate the list itself by duplicating an entry
             0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, true).inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate a list element,
             1,
             // mutate the second element,
             1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, false).inOrder();
  }
}
