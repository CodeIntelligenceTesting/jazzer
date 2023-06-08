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

package com.code_intelligence.jazzer.mutation.mutator;

import static com.code_intelligence.jazzer.mutation.mutator.Mutators.validateAnnotationUsage;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.lang.Math.floor;
import static java.lang.Math.pow;
import static java.lang.Math.sqrt;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.IntStream.rangeClosed;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.annotation.proto.AnySource;
import com.code_intelligence.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto2.TestProtobuf;
import com.code_intelligence.jazzer.protobuf.Proto3.AnyField3;
import com.code_intelligence.jazzer.protobuf.Proto3.BytesField3;
import com.code_intelligence.jazzer.protobuf.Proto3.DoubleField3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumField3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumField3.TestEnum;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldRepeated3;
import com.code_intelligence.jazzer.protobuf.Proto3.EnumFieldRepeated3.TestEnumRepeated;
import com.code_intelligence.jazzer.protobuf.Proto3.FloatField3;
import com.code_intelligence.jazzer.protobuf.Proto3.IntegralField3;
import com.code_intelligence.jazzer.protobuf.Proto3.MapField3;
import com.code_intelligence.jazzer.protobuf.Proto3.MessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.MessageMapField3;
import com.code_intelligence.jazzer.protobuf.Proto3.OptionalPrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedDoubleField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedFloatField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedIntegralField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedRecursiveMessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.SingleOptionOneOfField3;
import com.code_intelligence.jazzer.protobuf.Proto3.StringField3;
import com.google.protobuf.Any;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.JavaType;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class StressTest {
  private static final int NUM_INITS = 500;
  private static final int NUM_MUTATE_PER_INIT = 100;
  private static final double MANY_DISTINCT_ELEMENTS_RATIO = 0.5;

  private enum TestEnumTwo { A, B }

  private enum TestEnumThree { A, B, C }

  @SuppressWarnings("unused")
  static Message getTestProtobufDefaultInstance() {
    return TestProtobuf.getDefaultInstance();
  }

  public static Stream<Arguments> stressTestCases() {
    return Stream.of(arguments(asAnnotatedType(boolean.class), "Boolean", exactly(false, true),
                         exactly(false, true)),
        arguments(new TypeHolder<@NotNull Boolean>() {}.annotatedType(), "Boolean",
            exactly(false, true), exactly(false, true)),
        arguments(new TypeHolder<Boolean>() {}.annotatedType(), "Nullable<Boolean>",
            exactly(null, false, true), exactly(null, false, true)),
        arguments(new TypeHolder<@NotNull List<@NotNull Boolean>>() {}.annotatedType(),
            "List<Boolean>", exactly(emptyList(), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull List<Boolean>>() {}.annotatedType(),
            "List<Nullable<Boolean>>",
            exactly(emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(new TypeHolder<List<@NotNull Boolean>>() {}.annotatedType(),
            "Nullable<List<Boolean>>",
            exactly(null, emptyList(), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(new TypeHolder<List<Boolean>>() {}.annotatedType(),
            "Nullable<List<Nullable<Boolean>>>",
            exactly(
                null, emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<@NotNull Map<@NotNull String, @NotNull String>>() {}.annotatedType(),
            "Map<String,String>", distinctElementsRatio(0.45), distinctElementsRatio(0.45)),
        arguments(new TypeHolder<Map<@NotNull String, @NotNull String>>() {}.annotatedType(),
            "Nullable<Map<String,String>>", distinctElementsRatio(0.46),
            distinctElementsRatio(0.48)),
        arguments(
            new TypeHolder<@WithSize(max = 3) @NotNull Map<@NotNull Integer, @NotNull Integer>>() {
            }.annotatedType(),
            "Map<Integer,Integer>",
            // Half of all maps are empty, the other half is heavily biased towards special values.
            all(mapSizeInClosedRange(0, 3), distinctElementsRatio(0.2)),
            all(mapSizeInClosedRange(0, 3), manyDistinctElements())),
        arguments(
            new TypeHolder<@NotNull Map<@NotNull Boolean, @NotNull Boolean>>() {}.annotatedType(),
            "Map<Boolean,Boolean>",
            // 1 0-element map, 4 1-element maps
            distinctElements(1 + 4),
            // 1 0-element map, 4 1-element maps, 4 2-element maps
            distinctElements(1 + 4 + 4)),
        arguments(asAnnotatedType(byte.class), "Byte",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1 << Byte.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((byte) 0, (byte) 1, Byte.MIN_VALUE, Byte.MAX_VALUE)),
            // With mutations, we expect to reach all possible bytes.
            exactly(rangeClosed(Byte.MIN_VALUE, Byte.MAX_VALUE).mapToObj(i -> (byte) i).toArray())),
        arguments(asAnnotatedType(short.class), "Short",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1 << Short.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((short) 0, (short) 1, Short.MIN_VALUE, Short.MAX_VALUE)),
            // The integral type mutator does not always return uniformly random values and the
            // random walk it uses is more likely to produce non-distinct elements, hence the test
            // only passes with ~90% of the optimal parameters.
            expectedNumberOfDistinctElements(
                1 << Short.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(asAnnotatedType(int.class), "Integer",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(0, 1, Integer.MIN_VALUE, Integer.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(new TypeHolder<@NotNull @InRange(min = 0) Long>() {}.annotatedType(), "Long",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Long.SIZE - 1, boundHits(NUM_INITS, 0.2)),
                contains(0L, 1L, Long.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE - 1, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(
            new TypeHolder<@NotNull @InRange(max = Integer.MIN_VALUE + 5) Integer>() {
            }.annotatedType(),
            "Integer",
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray()),
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray())),
        arguments(asAnnotatedType(TestEnumTwo.class), "Nullable<Enum<TestEnumTwo>>",
            exactly(null, TestEnumTwo.A, TestEnumTwo.B),
            exactly(null, TestEnumTwo.A, TestEnumTwo.B)),
        arguments(asAnnotatedType(TestEnumThree.class), "Nullable<Enum<TestEnumThree>>",
            exactly(null, TestEnumThree.A, TestEnumThree.B, TestEnumThree.C),
            exactly(null, TestEnumThree.A, TestEnumThree.B, TestEnumThree.C)),
        arguments(new TypeHolder<@NotNull @FloatInRange(min = 0f) Float>() {}.annotatedType(),
            "Float",
            all(distinctElementsRatio(0.45),
                doesNotContain(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, -Float.MIN_VALUE),
                contains(Float.NaN, Float.POSITIVE_INFINITY, Float.MAX_VALUE, Float.MIN_VALUE, 0.0f,
                    -0.0f)),
            all(distinctElementsRatio(0.75),
                doesNotContain(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, -Float.MIN_VALUE))),
        arguments(new TypeHolder<@NotNull Float>() {}.annotatedType(), "Float",
            all(distinctElementsRatio(0.45),
                contains(Float.NaN, Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY,
                    -Float.MAX_VALUE, Float.MAX_VALUE, -Float.MIN_VALUE, Float.MIN_VALUE, 0.0f,
                    -0.0f)),
            distinctElementsRatio(0.76)),
        arguments(
            new TypeHolder<@NotNull @FloatInRange(
                min = -1.0f, max = 1.0f, allowNaN = false) Float>() {
            }.annotatedType(),
            "Float",
            all(distinctElementsRatio(0.45),
                doesNotContain(Float.NaN, -Float.MAX_VALUE, Float.MAX_VALUE,
                    Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY),
                contains(-Float.MIN_VALUE, Float.MIN_VALUE, 0.0f, -0.0f)),
            all(distinctElementsRatio(0.525),
                doesNotContain(Float.NaN, -Float.MAX_VALUE, Float.MAX_VALUE,
                    Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY),
                contains(-Float.MIN_VALUE, Float.MIN_VALUE, 0.0f, -0.0f))),
        arguments(new TypeHolder<@NotNull Double>() {}.annotatedType(), "Double",
            all(distinctElementsRatio(0.45),
                contains(Double.NaN, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY)),
            distinctElementsRatio(0.75)),
        arguments(
            new TypeHolder<@NotNull @DoubleInRange(
                min = -1.0, max = 1.0, allowNaN = false) Double>() {
            }.annotatedType(),
            "Double", all(distinctElementsRatio(0.45), doesNotContain(Double.NaN)),
            all(distinctElementsRatio(0.55), doesNotContain(Double.NaN))));
  }

  public static Stream<Arguments> protoStressTestCases() {
    return Stream.of(
        arguments(new TypeHolder<@NotNull OptionalPrimitiveField3>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>} -> Message",
            exactly(OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build()),
            exactly(OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build())),
        arguments(new TypeHolder<@NotNull RepeatedRecursiveMessageField3>() {}.annotatedType(),
            "{Builder.Boolean, WithoutInit(Builder via List<(cycle) -> Message>)} -> Message",
            // The message field is recursive and thus not initialized.
            exactly(RepeatedRecursiveMessageField3.getDefaultInstance(),
                RepeatedRecursiveMessageField3.newBuilder().setSomeField(true).build()),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull IntegralField3>() {}.annotatedType(),
            "{Builder.Integer} -> Message",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(IntegralField3.newBuilder().build(),
                    IntegralField3.newBuilder().setSomeField(1).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MIN_VALUE).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MAX_VALUE).build())),
            // Our mutations return uniformly random elements in ~3/8 of all cases.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 3 / 8)),
        arguments(new TypeHolder<@NotNull RepeatedIntegralField3>() {}.annotatedType(),
            "{Builder via List<Integer>} -> Message",
            contains(RepeatedIntegralField3.getDefaultInstance(),
                RepeatedIntegralField3.newBuilder().addSomeField(0).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(1).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MAX_VALUE).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MIN_VALUE).build()),
            // TODO: This ratio is on the lower end, most likely because of the strong bias towards
            //  special values combined with the small initial size of the list. When we improve the
            //  list mutator, this may be increased.
            distinctElementsRatio(0.25)),
        arguments(new TypeHolder<@NotNull BytesField3>() {}.annotatedType(),
            "{Builder.byte[] -> ByteString} -> Message", manyDistinctElements(),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull StringField3>() {}.annotatedType(),
            "{Builder.String} -> Message", manyDistinctElements(), manyDistinctElements()),
        arguments(new TypeHolder<@NotNull EnumField3>() {}.annotatedType(),
            "{Builder.Enum<TestEnum>} -> Message",
            exactly(EnumField3.getDefaultInstance(),
                EnumField3.newBuilder().setSomeField(TestEnum.VAL2).build()),
            exactly(EnumField3.getDefaultInstance(),
                EnumField3.newBuilder().setSomeField(TestEnum.VAL2).build())),
        arguments(new TypeHolder<@NotNull EnumFieldRepeated3>() {}.annotatedType(),
            "{Builder via List<Enum<TestEnumRepeated>>} -> Message",
            exactly(EnumFieldRepeated3.getDefaultInstance(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.UNASSIGNED).build(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.VAL1).build(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.VAL2).build()),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull MapField3>() {}.annotatedType(),
            "{Builder.Map<Integer,String>} -> Message", distinctElementsRatio(0.47),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull MessageMapField3>() {}.annotatedType(),
            "{Builder.Map<String,{Builder.Map<Integer,String>} -> Message>} -> Message",
            distinctElementsRatio(0.45), distinctElementsRatio(0.45)),
        arguments(new TypeHolder<@NotNull DoubleField3>() {}.annotatedType(),
            "{Builder.Double} -> Message", distinctElementsRatio(0.45), distinctElementsRatio(0.7)),
        arguments(new TypeHolder<@NotNull RepeatedDoubleField3>() {}.annotatedType(),
            "{Builder via List<Double>} -> Message", distinctElementsRatio(0.2),
            distinctElementsRatio(0.9)),
        arguments(new TypeHolder<@NotNull FloatField3>() {}.annotatedType(),
            "{Builder.Float} -> Message", distinctElementsRatio(0.45), distinctElementsRatio(0.7)),
        arguments(new TypeHolder<@NotNull RepeatedFloatField3>() {}.annotatedType(),
            "{Builder via List<Float>} -> Message", distinctElementsRatio(0.20),
            distinctElementsRatio(0.9), emptyList()),
        arguments(new TypeHolder<@NotNull TestProtobuf>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>, Builder.Nullable<Integer>, Builder.Nullable<Integer>, Builder.Nullable<Long>, Builder.Nullable<Long>, Builder.Nullable<Float>, Builder.Nullable<Double>, Builder.Nullable<String>, Builder.Nullable<Enum<Enum>>, WithoutInit(Builder.Nullable<{Builder.Nullable<Integer>, Builder via List<Integer>, WithoutInit(Builder.Nullable<(cycle) -> Message>)} -> Message>), Builder via List<Boolean>, Builder via List<Integer>, Builder via List<Integer>, Builder via List<Long>, Builder via List<Long>, Builder via List<Float>, Builder via List<Double>, Builder via List<String>, Builder via List<Enum<Enum>>, WithoutInit(Builder via List<(cycle) -> Message>), Builder.Map<Integer,Integer>, Builder.Nullable<FixedValue(OnlyLabel)>, Builder.Nullable<{<empty>} -> Message>, Builder.Nullable<Integer> | Builder.Nullable<Long> | Builder.Nullable<Integer>} -> Message",
            manyDistinctElements(), manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull @WithDefaultInstance(
                "com.code_intelligence.jazzer.mutation.mutator.StressTest#getTestProtobufDefaultInstance")
                Message>() {
            }.annotatedType(),
            "{Builder.Nullable<Boolean>, Builder.Nullable<Integer>, Builder.Nullable<Integer>, Builder.Nullable<Long>, Builder.Nullable<Long>, Builder.Nullable<Float>, Builder.Nullable<Double>, Builder.Nullable<String>, Builder.Nullable<Enum<Enum>>, WithoutInit(Builder.Nullable<{Builder.Nullable<Integer>, Builder via List<Integer>, WithoutInit(Builder.Nullable<(cycle) -> Message>)} -> Message>), Builder via List<Boolean>, Builder via List<Integer>, Builder via List<Integer>, Builder via List<Long>, Builder via List<Long>, Builder via List<Float>, Builder via List<Double>, Builder via List<String>, Builder via List<Enum<Enum>>, WithoutInit(Builder via List<(cycle) -> Message>), Builder.Map<Integer,Integer>, Builder.Nullable<FixedValue(OnlyLabel)>, Builder.Nullable<{<empty>} -> Message>, Builder.Nullable<Integer> | Builder.Nullable<Long> | Builder.Nullable<Integer>} -> Message",
            manyDistinctElements(), manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull @AnySource(
                {PrimitiveField3.class, MessageField3.class}) AnyField3>() {
            }.annotatedType(),
            "{Builder.Nullable<Builder.{Builder.Boolean} -> Message | Builder.{Builder.Nullable<(cycle) -> Message>} -> Message -> Message>} -> Message",
            exactly(AnyField3.getDefaultInstance(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(PrimitiveField3.getDefaultInstance()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(PrimitiveField3.newBuilder().setSomeField(true).build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(MessageField3.getDefaultInstance()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(
                        Any.pack(MessageField3.newBuilder()
                                     .setMessageField(PrimitiveField3.getDefaultInstance())
                                     .build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(
                        MessageField3.newBuilder()
                            .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                            .build()))
                    .build()),
            exactly(AnyField3.getDefaultInstance(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(PrimitiveField3.getDefaultInstance()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(PrimitiveField3.newBuilder().setSomeField(true).build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(MessageField3.getDefaultInstance()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(
                        Any.pack(MessageField3.newBuilder()
                                     .setMessageField(PrimitiveField3.getDefaultInstance())
                                     .build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(Any.pack(
                        MessageField3.newBuilder()
                            .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                            .build()))
                    .build())),
        arguments(new TypeHolder<@NotNull SingleOptionOneOfField3>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>} -> Message",
            exactly(SingleOptionOneOfField3.getDefaultInstance(),
                SingleOptionOneOfField3.newBuilder().setBoolField(false).build(),
                SingleOptionOneOfField3.newBuilder().setBoolField(true).build()),
            exactly(SingleOptionOneOfField3.getDefaultInstance(),
                SingleOptionOneOfField3.newBuilder().setBoolField(false).build(),
                SingleOptionOneOfField3.newBuilder().setBoolField(true).build())));
  }

  @SafeVarargs
  private static Consumer<List<Object>> all(Consumer<List<Object>>... checks) {
    return list -> {
      for (Consumer<List<Object>> check : checks) {
        check.accept(list);
      }
    };
  }

  private static Consumer<List<Object>> distinctElements(int num) {
    return list -> assertThat(new HashSet<>(list).size()).isAtLeast(num);
  }

  private static Consumer<List<Object>> manyDistinctElements() {
    return distinctElementsRatio(MANY_DISTINCT_ELEMENTS_RATIO);
  }

  /**
   * Returns a lower bound on the expected number of hits when sampling from a domain of a given
   * size with the given probability.
   */
  private static int boundHits(long domainSize, double probability) {
    // Binomial distribution.
    double expectedValue = domainSize * probability;
    double variance = domainSize * probability * (1 - probability);
    double standardDeviation = sqrt(variance);
    // Allow missing the expected value by two standard deviations. For a normal distribution,
    // this would correspond to 95% of all cases.
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    return almostCertainLowerBound;
  }

  /**
   * Asserts that a given list contains at least as many distinct elements as can be expected when
   * picking {@code picks} out of {@code domainSize} elements uniformly at random.
   */
  private static Consumer<List<Object>> expectedNumberOfDistinctElements(
      long domainSize, int picks) {
    // https://www.randomservices.org/random/urn/Birthday.html#mom2
    double expectedValue = domainSize * (1 - pow(1 - 1.0 / domainSize, picks));
    double variance = domainSize * (domainSize - 1) * pow(1 - 2.0 / domainSize, picks)
        + domainSize * pow(1 - 1.0 / domainSize, picks)
        - domainSize * domainSize * pow(1 - 1.0 / domainSize, 2 * picks);
    double standardDeviation = sqrt(variance);
    // Allow missing the expected value by two standard deviations. For a normal distribution,
    // this would correspond to 95% of all cases.
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    return list
        -> assertWithMessage("V=distinct elements among %s picked out of %s\nE[V]=%s\nσ[V]=%s",
            picks, domainSize, expectedValue, standardDeviation)
               .that(new HashSet<>(list).size())
               .isAtLeast(almostCertainLowerBound);
  }

  private static Consumer<List<Object>> distinctElementsRatio(double ratio) {
    require(ratio > 0);
    require(ratio <= 1);
    return list -> assertThat(new HashSet<>(list).size() / (double) list.size()).isAtLeast(ratio);
  }

  private static Consumer<List<Object>> exactly(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsExactly(expected);
  }

  private static Consumer<List<Object>> contains(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsAtLeastElementsIn(expected);
  }

  private static Consumer<List<Object>> doesNotContain(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsNoneIn(expected);
  }

  private static Consumer<List<Object>> mapSizeInClosedRange(int min, int max) {
    return list -> {
      list.forEach(map -> {
        if (map instanceof Map) {
          assertThat(((Map) map).size()).isAtLeast(min);
          assertThat(((Map) map).size()).isAtMost(max);
        } else {
          throw new IllegalArgumentException(
              "Expected a list of maps, got list of" + map.getClass().getName());
        }
      });
    };
  }

  @ParameterizedTest(name = "{index} {0}, {1}")
  @MethodSource({"stressTestCases", "protoStressTestCases"})
  void genericMutatorStressTest(AnnotatedType type, String mutatorTree,
      Consumer<List<Object>> expectedInitValues, Consumer<List<Object>> expectedMutatedValues)
      throws IOException {
    validateAnnotationUsage(type);
    SerializingMutator mutator = Mutators.newFactory().createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo(mutatorTree);

    // Even with a fallback to mutating map values when no new key can be constructed, the map
    // {false: true, true: false} will not change its equality class when the fallback picks both
    // values to mutate.
    boolean mayPerformNoopMutations =
        mutatorTree.contains("FixedValue(") || mutatorTree.contains("Map<Boolean,Boolean>");

    PseudoRandom rng = anyPseudoRandom();

    List<Object> initValues = new ArrayList<>();
    List<Object> mutatedValues = new ArrayList<>();
    for (int i = 0; i < NUM_INITS; i++) {
      Object value = mutator.init(rng);

      // For proto messages, each float field with value -0.0f, and double field with value -0.0
      // will be converted to 0.0f and 0.0, respectively.
      Object fixedValue = fixFloatingPointsForProtos(value);
      testReadWriteRoundtrip(mutator, fixedValue);
      testReadWriteExclusiveRoundtrip(mutator, fixedValue);

      initValues.add(mutator.detach(value));
      value = fixFloatingPointsForProtos(value);

      for (int mutation = 0; mutation < NUM_MUTATE_PER_INIT; mutation++) {
        Object detachedOldValue = mutator.detach(value);
        value = mutator.mutate(value, rng);
        if (!mayPerformNoopMutations) {
          if (value instanceof Double) {
            assertThat(Double.compare((Double) value, (Double) detachedOldValue)).isNotEqualTo(0);
          } else if (value instanceof Float) {
            assertThat(Float.compare((Float) value, (Float) detachedOldValue)).isNotEqualTo(0);
          } else {
            assertThat(detachedOldValue).isNotEqualTo(value);
          }
        }

        mutatedValues.add(mutator.detach(value));

        // For proto messages, each float field with value -0.0f, and double field with value -0.0
        // will be converted to 0.0f and 0.0, respectively. This is because the values -0f and 0f
        // and their double counterparts are serialized as default values (0f, and 0.0), which is
        // relevant for mutation and the round trip tests. This means that the protos with float or
        // double fields that equal to negative zero, will start mutation from positive zeros, and
        // cause the assertion above to fail from time to time. To avoid this, we convert all
        // negative zeros to positive zeros for float and double proto fields.
        value = fixFloatingPointsForProtos(value);
        testReadWriteRoundtrip(mutator, fixedValue);
        testReadWriteExclusiveRoundtrip(mutator, fixedValue);
      }
    }

    expectedInitValues.accept(initValues);
    expectedMutatedValues.accept(mutatedValues);
  }

  private static <T> void testReadWriteExclusiveRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.writeExclusive(value, out);
    T newValue = serializer.readExclusive(new ByteArrayInputStream(out.toByteArray()));
    assertThat(newValue).isEqualTo(value);
  }

  private static <T> void testReadWriteRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.write(value, new DataOutputStream(out));
    T newValue = serializer.read(
        new DataInputStream(extendWithZeros(new ByteArrayInputStream(out.toByteArray()))));
    assertThat(newValue).isEqualTo(value);
  }

  // Filter out floating point values -0.0f and -0.0 and replace them
  // by 0.0f and 0.0 respectively.
  // This is a workaround for a bug in the protobuf library that causes
  // our "...RoundTrip" tests to fail for negative zero in floats and doubles.
  private static <T> T fixFloatingPointsForProtos(T value) {
    if (!(value instanceof Message)) {
      return value;
    }
    Message.Builder builder = ((Message) value).toBuilder();
    walkFields(builder, oldValue -> {
      if (Objects.equals(oldValue, -0.0)) {
        return 0.0;
      } else if (Objects.equals(oldValue, -0.0f)) {
        return 0.0f;
      } else {
        return oldValue;
      }
    });
    return (T) builder.build();
  }

  private static void walkFields(Builder builder, Function<Object, Object> transform) {
    for (FieldDescriptor field : builder.getDescriptorForType().getFields()) {
      if (field.isRepeated()) {
        int bound = builder.getRepeatedFieldCount(field);
        for (int i = 0; i < bound; i++) {
          if (field.getJavaType() == JavaType.MESSAGE) {
            Builder repeatedFieldBuilder =
                ((Message) builder.getRepeatedField(field, i)).toBuilder();
            walkFields(repeatedFieldBuilder, transform);
            builder.setRepeatedField(field, i, repeatedFieldBuilder.build());
          } else {
            builder.setRepeatedField(field, i, transform.apply(builder.getRepeatedField(field, i)));
          }
        }
      } else if (field.getJavaType() == JavaType.MESSAGE) {
        // Break up unbounded recursion.
        if (!builder.hasField(field)) {
          continue;
        }
        Builder fieldBuilder = ((Message) builder.getField(field)).toBuilder();
        walkFields(fieldBuilder, transform);
        builder.setField(field, fieldBuilder.build());
      } else {
        builder.setField(field, transform.apply(builder.getField(field)));
      }
    }
  }
}
