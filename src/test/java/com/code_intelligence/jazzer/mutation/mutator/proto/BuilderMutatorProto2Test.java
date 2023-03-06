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
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto2.MessageField2;
import com.code_intelligence.jazzer.protobuf.Proto2.OneOfField2;
import com.code_intelligence.jazzer.protobuf.Proto2.PrimitiveField2;
import com.code_intelligence.jazzer.protobuf.Proto2.RecursiveMessageField2;
import com.code_intelligence.jazzer.protobuf.Proto2.RepeatedMessageField2;
import com.code_intelligence.jazzer.protobuf.Proto2.RepeatedOptionalMessageField2;
import com.code_intelligence.jazzer.protobuf.Proto2.RepeatedPrimitiveField2;
import com.code_intelligence.jazzer.protobuf.Proto2.RequiredPrimitiveField2;
import org.junit.jupiter.api.Test;

class BuilderMutatorProto2Test {
  private static final MutatorFactory FACTORY = new ChainedMutatorFactory(
      LangMutators.newFactory(), CollectionMutators.newFactory(), ProtoMutators.newFactory());

  @Test
  void testPrimitiveField() {
    InPlaceMutator<PrimitiveField2.Builder> mutator =
        (InPlaceMutator<PrimitiveField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<PrimitiveField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<Boolean>}");

    PrimitiveField2.Builder builder = PrimitiveField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // present
             false,
             // boolean
             false)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // present
             false,
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
             false)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // not present
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isFalse();
    assertThat(builder.getSomeField()).isFalse();
  }

  @Test
  void testRequiredPrimitiveField() {
    InPlaceMutator<RequiredPrimitiveField2.Builder> mutator =
        (InPlaceMutator<RequiredPrimitiveField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RequiredPrimitiveField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Boolean}");

    RequiredPrimitiveField2.Builder builder = RequiredPrimitiveField2.newBuilder();

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
  void testRepeatedPrimitiveField() {
    InPlaceMutator<RepeatedPrimitiveField2.Builder> mutator =
        (InPlaceMutator<RepeatedPrimitiveField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RepeatedPrimitiveField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<Boolean>}");

    RepeatedPrimitiveField2.Builder builder = RepeatedPrimitiveField2.newBuilder();

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
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, true).inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate a list element,
             false,
             // mutate the second element,
             1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, false).inOrder();
  }
  @Test
  void testMessageField() {
    InPlaceMutator<MessageField2.Builder> mutator =
        (InPlaceMutator<MessageField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<MessageField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<{Builder.Boolean}>}");

    MessageField2.Builder builder = MessageField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // init submessage
             false,
             // boolean submessage field
             true)) {
      mutator.initInPlace(builder, prng);
    }

    assertThat(builder.getMessageField())
        .isEqualTo(RequiredPrimitiveField2.newBuilder().setSomeField(true).build());
    assertThat(builder.hasMessageField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate submessage as non-null
             false,
             // mutate first field
             0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageField())
        .isEqualTo(RequiredPrimitiveField2.newBuilder().setSomeField(false).build());
    assertThat(builder.hasMessageField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate submessage to null
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.hasMessageField()).isFalse();
  }

  @Test
  void testRepeatedOptionalMessageField() {
    InPlaceMutator<RepeatedOptionalMessageField2.Builder> mutator =
        (InPlaceMutator<RepeatedOptionalMessageField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RepeatedOptionalMessageField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<{Builder.Nullable<Boolean>}>}");

    RepeatedOptionalMessageField2.Builder builder = RepeatedOptionalMessageField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // list size 1
             1,
             // boolean
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList().toString()).isEqualTo("[]");

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate the list itself by duplicating an entry
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList().size()).isEqualTo(2);
  }

  @Test
  void testRepeatedRequiredMessageField() {
    InPlaceMutator<RepeatedMessageField2.Builder> mutator =
        (InPlaceMutator<RepeatedMessageField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RepeatedMessageField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<{Builder.Boolean}>}");

    RepeatedMessageField2.Builder builder = RepeatedMessageField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // list size 1
             1,
             // boolean
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(RequiredPrimitiveField2.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate the list itself by duplicating an entry
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(RequiredPrimitiveField2.newBuilder().setSomeField(true).build(),
            RequiredPrimitiveField2.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate a list element
             false,
             // mutate the second element
             1,
             // mutate the first field
             0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(RequiredPrimitiveField2.newBuilder().setSomeField(true).build(),
            RequiredPrimitiveField2.newBuilder().setSomeField(false).build())
        .inOrder();
  }

  @Test
  void testRecursiveMessageField() {
    InPlaceMutator<RecursiveMessageField2.Builder> mutator =
        (InPlaceMutator<RecursiveMessageField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RecursiveMessageField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Boolean, Builder.Nullable<(cycle)>}");
    RecursiveMessageField2.Builder builder = RecursiveMessageField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // boolean
             true,
             // message field is not null
             false,
             // nested boolean,
             false,
             // nested message field is not set
             true)) {
      mutator.initInPlace(builder, prng);
    }

    // Nested message field is *not* set explicitly and implicitly equal to the
    // default instance.
    assertThat(builder.build())
        .isEqualTo(RecursiveMessageField2.newBuilder()
                       .setSomeField(true)
                       .setMessageField(RecursiveMessageField2.newBuilder().setSomeField(false))
                       .build());
    assertThat(builder.getMessageFieldBuilder().hasMessageField()).isFalse();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate message field
             1,
             // mutate message field as not null
             false,
             // mutate message field
             1,
             // nested boolean,
             false,
             // nested message field is null
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    // Nested message field *is* set explicitly and implicitly equal to the default
    // instance.
    assertThat(builder.build())
        .isEqualTo(RecursiveMessageField2.newBuilder()
                       .setSomeField(true)
                       .setMessageField(
                           RecursiveMessageField2.newBuilder().setSomeField(false).setMessageField(
                               RecursiveMessageField2.newBuilder().setSomeField(false)))
                       .build());
    assertThat(builder.getMessageField().hasMessageField()).isTrue();
  }

  @Test
  void testOneOfField2() {
    InPlaceMutator<OneOfField2.Builder> mutator =
        (InPlaceMutator<OneOfField2.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<OneOfField2.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "{Builder.Boolean, Builder.Nullable<Boolean>, Builder.Nullable<Boolean> | Builder.Nullable<{Builder.Boolean}>}");
    OneOfField2.Builder builder = OneOfField2.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // other_field
             true,
             // yet_another_field
             true,
             // oneof: first field
             0,
             // bool_field present
             false,
             // bool_field
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(OneOfField2.newBuilder().setOtherField(true).setBoolField(true).build());
    assertThat(builder.build().hasBoolField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate oneof
             2,
             // preserve oneof state
             false,
             // mutate bool_field as non-null
             false)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(OneOfField2.newBuilder().setOtherField(true).setBoolField(false).build());
    assertThat(builder.build().hasBoolField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate oneof
             2,
             // switch oneof state
             true,
             // new oneof state
             1,
             // init message_field as non-null
             false,
             // init some_field as true
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(OneOfField2.newBuilder()
                       .setOtherField(true)
                       .setMessageField(RequiredPrimitiveField2.newBuilder().setSomeField(true))
                       .build());
    assertThat(builder.build().hasMessageField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate oneof
             2,
             // preserve oneof state
             false,
             // mutate message_field as non-null
             false,
             // mutate some_field
             0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(OneOfField2.newBuilder()
                       .setOtherField(true)
                       .setMessageField(RequiredPrimitiveField2.newBuilder().setSomeField(false))
                       .build());
    assertThat(builder.build().hasMessageField()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate oneof
             2,
             // preserve oneof state
             false,
             // mutate message_field to null (and thus oneof state to indeterminate)
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build()).isEqualTo(OneOfField2.newBuilder().setOtherField(true).build());
    assertThat(builder.build().hasMessageField()).isFalse();
  }
}
