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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.proto.AnySource;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto3.AnyField3;
import com.code_intelligence.jazzer.protobuf.Proto3.AnyField3.Builder;
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
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BuilderMutatorProto3Test {
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
  void testPrimitiveField() {
    InPlaceMutator<PrimitiveField3.Builder> mutator =
        (InPlaceMutator<PrimitiveField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<PrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Boolean}");
    assertThat(mutator.hasFixedSize()).isTrue();

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
        (InPlaceMutator<EnumField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<EnumField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Enum<TestEnum>}");
    assertThat(mutator.hasFixedSize()).isTrue();
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
        (InPlaceMutator<EnumFieldOutside3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<EnumFieldOutside3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Enum<TestEnumOutside3>}");
    assertThat(mutator.hasFixedSize()).isTrue();
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
        (InPlaceMutator<EnumFieldOne3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<EnumFieldOne3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.FixedValue(ONE)}");
    assertThat(mutator.hasFixedSize()).isTrue();
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
        (InPlaceMutator<EnumFieldRepeated3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<EnumFieldRepeated3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<Enum<TestEnumRepeated>>}");
    assertThat(mutator.hasFixedSize()).isFalse();
    EnumFieldRepeated3.Builder builder = EnumFieldRepeated3.newBuilder();
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // list size
            1, // Only possible start value
            // enum values
            2)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).isEqualTo(Arrays.asList(TestEnumRepeated.VAL2));

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // change an entry
            2,
            // mutate a single element
            1,
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
        (InPlaceMutator<OptionalPrimitiveField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<OptionalPrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<Boolean>}");
    assertThat(mutator.hasFixedSize()).isTrue();

    OptionalPrimitiveField3.Builder builder = OptionalPrimitiveField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // present
            false,
            // boolean
            false)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // present
            false,
            // boolean
            true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // mutate as non-null Boolean
            false)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.hasSomeField()).isTrue();
    assertThat(builder.getSomeField()).isFalse();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        (InPlaceMutator<RepeatedPrimitiveField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<RepeatedPrimitiveField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<Boolean>}");
    assertThat(mutator.hasFixedSize()).isFalse();

    RepeatedPrimitiveField3.Builder builder = RepeatedPrimitiveField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // list size 1
            1,
            // boolean,
            true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true).inOrder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // mutate the list itself by adding an entry
            1,
            // add a single element
            1,
            // add the element at the end
            1,
            // value to add
            true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, true).inOrder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // mutate the list itself by changing an entry
            2,
            // mutate a single element
            1,
            // mutate the second element
            1)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getSomeFieldList()).containsExactly(true, false).inOrder();
  }

  @Test
  void testMessageField() {
    InPlaceMutator<MessageField3.Builder> mutator =
        (InPlaceMutator<MessageField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<MessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder.Nullable<{Builder.Boolean} -> Message>}");
    assertThat(mutator.hasFixedSize()).isTrue();

    MessageField3.Builder builder = MessageField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // init submessage
            false,
            // boolean submessage field
            true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageField())
        .isEqualTo(PrimitiveField3.newBuilder().setSomeField(true).build());
    assertThat(builder.hasMessageField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        (InPlaceMutator<RepeatedMessageField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<RepeatedMessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{Builder via List<{Builder.Boolean} -> Message>}");
    assertThat(mutator.hasFixedSize()).isFalse();

    RepeatedMessageField3.Builder builder = RepeatedMessageField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // list size 1
            1,
            // boolean
            true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(PrimitiveField3.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // mutate the list itself by adding an entry
            1,
            // add a single element
            1,
            // add the element at the end
            1,
            // value to add
            true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(
            PrimitiveField3.newBuilder().setSomeField(true).build(),
            PrimitiveField3.newBuilder().setSomeField(true).build())
        .inOrder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first field
            0,
            // change an entry
            2,
            // mutate a single element
            1,
            // mutate the second element,
            1,
            // mutate the first element
            0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.getMessageFieldList())
        .containsExactly(
            PrimitiveField3.newBuilder().setSomeField(true).build(),
            PrimitiveField3.newBuilder().setSomeField(false).build())
        .inOrder();
  }

  @Test
  void testRecursiveMessageField() {
    InPlaceMutator<RecursiveMessageField3.Builder> mutator =
        (InPlaceMutator<RecursiveMessageField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<RecursiveMessageField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("{Builder.Boolean, WithoutInit(Builder.Nullable<(cycle) -> Message>)}");
    assertThat(mutator.hasFixedSize()).isFalse();
    RecursiveMessageField3.Builder builder = RecursiveMessageField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // boolean
            true)) {
      mutator.initInPlace(builder, prng);
    }

    assertThat(builder.build())
        .isEqualTo(RecursiveMessageField3.newBuilder().setSomeField(true).build());
    assertThat(builder.hasMessageField()).isFalse();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate message field (causes init to non-null)
            1,
            // bool field in message field
            false)) {
      mutator.mutateInPlace(builder, prng);
    }
    // Nested message field *is* set explicitly and implicitly equal to the default
    // instance.
    assertThat(builder.build())
        .isEqualTo(
            RecursiveMessageField3.newBuilder()
                .setSomeField(true)
                .setMessageField(RecursiveMessageField3.newBuilder().setSomeField(false))
                .build());
    assertThat(builder.hasMessageField()).isTrue();
    assertThat(builder.getMessageField().hasMessageField()).isFalse();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate message field
            1,
            //  message field as not null
            false,
            // mutate message field
            1,
            // nested boolean,
            true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(
            RecursiveMessageField3.newBuilder()
                .setSomeField(true)
                .setMessageField(
                    RecursiveMessageField3.newBuilder()
                        .setSomeField(false)
                        .setMessageField(RecursiveMessageField3.newBuilder().setSomeField(true)))
                .build());
    assertThat(builder.hasMessageField()).isTrue();
    assertThat(builder.getMessageField().hasMessageField()).isTrue();
    assertThat(builder.getMessageField().getMessageField().hasMessageField()).isFalse();
  }

  @Test
  void testOneOfField3() {
    InPlaceMutator<OneOfField3.Builder> mutator =
        (InPlaceMutator<OneOfField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<OneOfField3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "{Builder.Boolean, Builder.Boolean, Builder.Nullable<Boolean> |"
                + " Builder.Nullable<{Builder.Boolean} -> Message>}");
    assertThat(mutator.hasFixedSize()).isTrue();
    OneOfField3.Builder builder = OneOfField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        .isEqualTo(
            OneOfField3.newBuilder()
                .setOtherField(true)
                .setBoolField(true)
                .setYetAnotherField(true)
                .build());
    assertThat(builder.build().hasBoolField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate oneof
            2,
            // preserve oneof state
            false,
            // mutate bool_field as non-null
            false)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build())
        .isEqualTo(
            OneOfField3.newBuilder()
                .setOtherField(true)
                .setBoolField(false)
                .setYetAnotherField(true)
                .build());
    assertThat(builder.build().hasBoolField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        .isEqualTo(
            OneOfField3.newBuilder()
                .setOtherField(true)
                .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                .setYetAnotherField(true)
                .build());
    assertThat(builder.build().hasMessageField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        .isEqualTo(
            OneOfField3.newBuilder()
                .setOtherField(true)
                .setMessageField(PrimitiveField3.newBuilder().setSomeField(false))
                .setYetAnotherField(true)
                .build());
    assertThat(builder.build().hasMessageField()).isTrue();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
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
        (InPlaceMutator<EmptyMessage3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<EmptyMessage3.@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("{<empty>}");
    assertThat(mutator.hasFixedSize()).isTrue();
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

  @Test
  void testAnyField3() throws InvalidProtocolBufferException {
    InPlaceMutator<AnyField3.Builder> mutator =
        (InPlaceMutator<AnyField3.Builder>)
            factory.createInPlaceOrThrow(
                new TypeHolder<
                    @NotNull @AnySource({PrimitiveField3.class, MessageField3.class})
                    Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "{Builder.Nullable<Builder.{Builder.Boolean} -> Message |"
                + " Builder.{Builder.Nullable<(cycle) -> Message>} -> Message -> Message>}");
    assertThat(mutator.hasFixedSize()).isTrue();
    AnyField3.Builder builder = AnyField3.newBuilder();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // initialize message field
            false,
            // PrimitiveField3
            0,
            // boolean field
            true)) {
      mutator.initInPlace(builder, prng);
    }
    assertThat(builder.build().getSomeField().unpack(PrimitiveField3.class))
        .isEqualTo(PrimitiveField3.newBuilder().setSomeField(true).build());

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate Any field
            0,
            // keep non-null message field
            false,
            // keep Any state,
            false,
            // mutate boolean field
            0)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build().getSomeField().unpack(PrimitiveField3.class))
        .isEqualTo(PrimitiveField3.newBuilder().setSomeField(false).build());

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate Any field
            0,
            // keep non-null message field
            false,
            // switch Any state
            true,
            // new Any state
            1,
            // non-null message
            false,
            // boolean field,
            true)) {
      mutator.mutateInPlace(builder, prng);
    }
    assertThat(builder.build().getSomeField().unpack(MessageField3.class))
        .isEqualTo(
            MessageField3.newBuilder()
                .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                .build());
  }

  @Test
  void testAnyField3WithoutAnySourceDoesNotCrash() throws InvalidProtocolBufferException {
    InPlaceMutator<AnyField3.Builder> mutator =
        (InPlaceMutator<AnyField3.Builder>)
            factory.createInPlaceOrThrow(new TypeHolder<@NotNull Builder>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("{Builder.Nullable<{Builder.String, Builder.byte[] -> ByteString} -> Message>}");
  }
}
