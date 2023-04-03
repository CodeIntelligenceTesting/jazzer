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
import com.code_intelligence.jazzer.protobuf.Proto3.EmptyMessage3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumField3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumField3.TestEnum;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldOne3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldOne3.TestEnumOne;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldOutside3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldRepeated3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldRepeated3.TestEnumRepeated;
import com.code_intelligence.jazzer.protobuf.Proto3.MessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.OneOfField3;
import com.code_intelligence.jazzer.protobuf.Proto3.OptionalPrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RecursiveMessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedMessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedPrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.TestEnumOutside3;
import java.util.Arrays;
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
  void testEnumField() {
    InPlaceMutator<EnumField3.Builder> mutator =
        (InPlaceMutator<EnumField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<EnumField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Enum<TestEnum>}");
    EnumField3.Builder builder = EnumField3.newBuilder();
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnum.VAL1);
    try (MockPseudoRandom prng = mockPseudoRandom(0, 1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnum.VAL2);
  }

  @Test
  void testEnumFieldOutside() {
    InPlaceMutator<EnumFieldOutside3.Builder> mutator =
        (InPlaceMutator<EnumFieldOutside3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<EnumFieldOutside3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Enum<TestEnumOutside3>}");
    EnumFieldOutside3.Builder builder = EnumFieldOutside3.newBuilder();
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnumOutside3.VAL1);
    try (MockPseudoRandom prng = mockPseudoRandom(0, 2)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnumOutside3.VAL3);
  }

  @Test
  void testEnumFieldWithOneValue() {
    InPlaceMutator<EnumFieldOne3.Builder> mutator =
        (InPlaceMutator<EnumFieldOne3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<EnumFieldOne3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.FixedValue(ONE)}");
    EnumFieldOne3.Builder builder = EnumFieldOne3.newBuilder();
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnumOne.ONE);
    try (MockPseudoRandom prng = mockPseudoRandom(0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeField()).isEqualTo(TestEnumOne.ONE);
  }

  @Test
  void testRepeatedEnumField() {
    InPlaceMutator<EnumFieldRepeated3.Builder> mutator =
        (InPlaceMutator<EnumFieldRepeated3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<EnumFieldRepeated3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<Enum<TestEnumRepeated>>}");
    EnumFieldRepeated3.Builder builder = EnumFieldRepeated3.newBuilder();
    try (MockPseudoRandom prng = mockPseudoRandom(
             // list size
             1, // Only possible start value
             // enum values
             2)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).isEqualTo(Arrays.asList(TestEnumRepeated.VAL2));

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // change an entry
             4,
             // mutate to first enum field
             0,
             // mutate to first enum value
             1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).isEqualTo(Arrays.asList(TestEnumRepeated.VAL1));
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
             // mutate the list itself by adding an element
             2,
             // value to add
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, true).inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate the list itself by changing an entry
             4,
             // mutate the second element,
             1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, false).inOrder();
  }

  @Test
  void testMessageField() {
    InPlaceMutator<MessageField3.Builder> mutator =
        (InPlaceMutator<MessageField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<MessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<{Builder.Boolean} -> Message>}");

    MessageField3.Builder builder = MessageField3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // init submessage
             false,
             // boolean submessage field
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageField())
        .isEqualTo(PrimitiveField3.newBuilder().setSomeField(true).build());
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
        .isEqualTo(PrimitiveField3.newBuilder().setSomeField(false).build());
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
  void testRepeatedMessageField() {
    InPlaceMutator<RepeatedMessageField3.Builder> mutator =
        (InPlaceMutator<RepeatedMessageField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RepeatedMessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<{Builder.Boolean} -> Message>}");

    RepeatedMessageField3.Builder builder = RepeatedMessageField3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // list size 1
             1,
             // boolean
             true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(PrimitiveField3.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // mutate the list itself by adding an entry
             2,
             // value to add
             true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(PrimitiveField3.newBuilder().setSomeField(true).build(),
            PrimitiveField3.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng = mockPseudoRandom(
             // mutate first field
             0,
             // change an entry
             4,
             // mutate the second element,
             1,
             // mutate the first element
             0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(PrimitiveField3.newBuilder().setSomeField(true).build(),
            PrimitiveField3.newBuilder().setSomeField(false).build())
        .inOrder();
  }

  @Test
  void testRecursiveMessageField() {
    InPlaceMutator<RecursiveMessageField3.Builder> mutator =
        (InPlaceMutator<RecursiveMessageField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<RecursiveMessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("{Builder.Boolean, Builder.Nullable<(cycle) -> Message>}");
    RecursiveMessageField3.Builder builder = RecursiveMessageField3.newBuilder();

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
        .isEqualTo(RecursiveMessageField3.newBuilder()
                       .setSomeField(true)
                       .setMessageField(RecursiveMessageField3.newBuilder())
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
        .isEqualTo(RecursiveMessageField3.newBuilder()
                       .setSomeField(true)
                       .setMessageField(RecursiveMessageField3.newBuilder().setMessageField(
                           RecursiveMessageField3.newBuilder()))
                       .build());
    assertThat(builder.getMessageField().hasMessageField()).isTrue();
  }

  @Test
  void testOneOfField3() {
    InPlaceMutator<OneOfField3.Builder> mutator =
        (InPlaceMutator<OneOfField3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<OneOfField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "{Builder.Boolean, Builder.Boolean, Builder.Nullable<Boolean> | Builder.Nullable<{Builder.Boolean} -> Message>}");
    OneOfField3.Builder builder = OneOfField3.newBuilder();

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
        .isEqualTo(OneOfField3.newBuilder()
                       .setOtherField(true)
                       .setBoolField(true)
                       .setYetAnotherField(true)
                       .build());
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
        .isEqualTo(OneOfField3.newBuilder()
                       .setOtherField(true)
                       .setBoolField(false)
                       .setYetAnotherField(true)
                       .build());
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
        .isEqualTo(OneOfField3.newBuilder()
                       .setOtherField(true)
                       .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                       .setYetAnotherField(true)
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
        .isEqualTo(OneOfField3.newBuilder()
                       .setOtherField(true)
                       .setMessageField(PrimitiveField3.newBuilder().setSomeField(false))
                       .setYetAnotherField(true)
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
    assertThat(builder.build())
        .isEqualTo(OneOfField3.newBuilder().setOtherField(true).setYetAnotherField(true).build());
    assertThat(builder.build().hasMessageField()).isFalse();
  }

  @Test
  void testEmptyMessage3() {
    InPlaceMutator<EmptyMessage3.Builder> mutator =
        (InPlaceMutator<EmptyMessage3.Builder>) FACTORY.createInPlaceOrThrow(
            new TypeHolder<EmptyMessage3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{<empty>}");
    EmptyMessage3.Builder builder = EmptyMessage3.newBuilder();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.build()).isEqualTo(EmptyMessage3.getDefaultInstance());

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build()).isEqualTo(EmptyMessage3.getDefaultInstance());
  }
}
