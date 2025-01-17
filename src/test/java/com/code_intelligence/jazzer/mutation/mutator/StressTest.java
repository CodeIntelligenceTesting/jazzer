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

import static com.code_intelligence.jazzer.mutation.support.AnnotationSupport.validateAnnotationUsage;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.asMap;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.lang.Math.floor;
import static java.lang.Math.pow;
import static java.lang.Math.sqrt;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.IntStream.rangeClosed;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.annotation.proto.AnySource;
import com.code_intelligence.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.ParameterHolder;
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
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.JavaType;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Array;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
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

@SuppressWarnings({"unused", "unchecked", "SameParameterValue"})
public class StressTest {
  private static final int NUM_INITS = 400;
  private static final int NUM_MUTATE_PER_INIT = 80;
  private static final double MANY_DISTINCT_ELEMENTS_RATIO = 0.5;

  private enum TestEnumTwo {
    A,
    B
  }

  private enum TestEnumThree {
    A,
    B,
    C
  }

  private record SimpleRecord(int i, boolean b) {}

  private record RepeatedRecord(SimpleRecord first, SimpleRecord second) {}

  private record LinkedListNode(SimpleRecord value, LinkedListNode next) {}

  private sealed interface Sealed {
    sealed interface A extends Sealed {
      record A1(@NotNull boolean b) implements A {}
    }

    abstract sealed class B implements Sealed {
      static final class B1 extends B {
        private final boolean b;

        B1(boolean b) {
          this.b = b;
        }

        @NotNull
        public boolean b() {
          return b;
        }

        @Override
        public boolean equals(Object o) {
          if (this == o) return true;
          if (o == null || getClass() != o.getClass()) return false;
          B1 b1 = (B1) o;
          return b == b1.b;
        }

        @Override
        public int hashCode() {
          return Objects.hash(b);
        }

        @Override
        public String toString() {
          return "B1{" + "b=" + b + '}';
        }
      }

      static final class B2 extends B {
        private final boolean b;

        B2(boolean b) {
          this.b = b;
        }

        @NotNull
        public boolean b() {
          return b;
        }

        @Override
        public boolean equals(Object o) {
          if (this == o) return true;
          if (o == null || getClass() != o.getClass()) return false;
          B2 b1 = (B2) o;
          return b == b1.b;
        }

        @Override
        public int hashCode() {
          return Objects.hash(b);
        }

        @Override
        public String toString() {
          return "B2{" + "b=" + b + '}';
        }
      }
    }

    sealed interface C extends Sealed {
      record C1(@NotNull boolean b) implements C {}

      record C2(@NotNull int i) implements C {}
    }
  }

  public static class SomeSetterBasedBean {
    protected long quz;

    public long getQuz() {
      return quz;
    }

    public void setQuz(long quz) {
      this.quz = quz;
    }
  }

  public static class SetterBasedBeanWithParent extends SomeSetterBasedBean {
    private boolean foo;
    private String bar;
    private int baz;

    public boolean isFoo() {
      return foo;
    }

    public void setFoo(boolean foo) {
      this.foo = foo;
    }

    public String getBar() {
      return bar;
    }

    public int getBaz() {
      return baz;
    }

    // Out-of-order setters are supported.
    public void setBaz(int baz) {
      this.baz = baz;
    }

    // Chainable setters are supported.
    public SetterBasedBeanWithParent setBar(String bar) {
      this.bar = bar;
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      SetterBasedBeanWithParent that = (SetterBasedBeanWithParent) o;
      return quz == that.quz && foo == that.foo && baz == that.baz && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(quz, foo, bar, baz);
    }

    @Override
    public String toString() {
      return "SetterBasedBeanWithParent{quz="
          + quz
          + ", foo="
          + foo
          + ", bar='"
          + bar
          + "', baz="
          + baz
          + '}';
    }
  }

  public static class LinkedListBean {
    private LinkedListBean next;
    private int value;

    public LinkedListBean getNext() {
      return next;
    }

    public void setNext(LinkedListBean next) {
      this.next = next;
    }

    public int getValue() {
      return value;
    }

    public void setValue(int value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      LinkedListBean that = (LinkedListBean) o;
      return value == that.value && Objects.equals(next, that.next);
    }

    @Override
    public int hashCode() {
      return Objects.hash(next, value);
    }

    @Override
    public String toString() {
      return "LinkedListBean{" + "next=" + next + ", value=" + value + '}';
    }
  }

  public static class ImmutableBuilder {
    private final int i;
    private final boolean b;

    public ImmutableBuilder() {
      this(0, false);
    }

    private ImmutableBuilder(int i, boolean b) {
      this.i = i;
      this.b = b;
    }

    public int getI() {
      return i;
    }

    public boolean isB() {
      return b;
    }

    public ImmutableBuilder withI(int i) {
      return new ImmutableBuilder(i, b);
    }

    // Both withX and setX are supported on immutable builders.
    public ImmutableBuilder setB(boolean b) {
      return new ImmutableBuilder(i, b);
    }

    @Override
    @SuppressWarnings("PatternVariableCanBeUsed")
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof ImmutableBuilder)) return false;
      ImmutableBuilder that = (ImmutableBuilder) o;
      return i == that.i && b == that.b;
    }

    @Override
    public int hashCode() {
      return Objects.hash(i, b);
    }

    @Override
    public String toString() {
      return "ImmutableBuilder{" + "i=" + i + ", b=" + b + '}';
    }
  }

  public static class ConstructorBasedBean {
    private final boolean foo;
    private final String bar;
    private final int baz;

    ConstructorBasedBean(boolean foo, String bar, int baz) {
      this.foo = foo;
      this.bar = bar;
      this.baz = baz;
    }

    boolean isFoo() {
      return foo;
    }

    public String getBar() {
      return bar;
    }

    public int getBaz() {
      return baz;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      ConstructorBasedBean that = (ConstructorBasedBean) o;
      return foo == that.foo && baz == that.baz && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(foo, bar, baz);
    }

    @Override
    public String toString() {
      return "ConstructorBasedBean{" + "foo=" + foo + ", bar='" + bar + '\'' + ", baz=" + baz + '}';
    }
  }

  public static class OnlyConstructorBean {
    private final String foo;
    private final List<Integer> bar;
    private final boolean baz;

    OnlyConstructorBean(String foo, List<Integer> bar, boolean baz) {
      this.foo = foo;
      this.bar = bar;
      this.baz = baz;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      OnlyConstructorBean that = (OnlyConstructorBean) o;
      return baz == that.baz && Objects.equals(foo, that.foo) && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(foo, bar, baz);
    }

    @Override
    public String toString() {
      return "OnlyConstructorBean{" + "foo='" + foo + '\'' + ", bar=" + bar + ", baz=" + baz + '}';
    }
  }

  public static class SuperBuilderTarget {
    private final String foo;

    protected SuperBuilderTarget(SuperBuilderTargetBuilder<?, ?> b) {
      this.foo = b.foo;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      SuperBuilderTarget that = (SuperBuilderTarget) o;
      return Objects.equals(foo, that.foo);
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(foo);
    }

    public static SuperBuilderTargetBuilder<?, ?> builder() {
      return new SuperBuilderTargetBuilderImpl();
    }

    public abstract static class SuperBuilderTargetBuilder<
        C extends SuperBuilderTarget, B extends SuperBuilderTargetBuilder<C, B>> {
      private String foo;

      public SuperBuilderTargetBuilder() {}

      public B foo(String foo) {
        this.foo = foo;
        return this.self();
      }

      protected abstract B self();

      public abstract C build();

      public String toString() {
        return "SuperBuilderTargetBuilder(foo=" + this.foo + ")";
      }
    }

    private static final class SuperBuilderTargetBuilderImpl
        extends SuperBuilderTargetBuilder<SuperBuilderTarget, SuperBuilderTargetBuilderImpl> {
      private SuperBuilderTargetBuilderImpl() {}

      protected SuperBuilderTargetBuilderImpl self() {
        return this;
      }

      public SuperBuilderTarget build() {
        return new SuperBuilderTarget(this);
      }
    }
  }

  @SuppressWarnings("unused")
  static Message getTestProtobufDefaultInstance() {
    return TestProtobuf.getDefaultInstance();
  }

  public static Stream<Arguments> stressTestCases() {
    return Stream.of(
        arguments(
            new ParameterHolder() {
              void singleParam(boolean parameter) {}
            }.annotatedType(),
            "Boolean",
            true,
            exactly(false, true),
            exactly(false, true)),
        arguments(
            new TypeHolder<@NotNull Boolean>() {}.annotatedType(),
            "Boolean",
            true,
            exactly(false, true),
            exactly(false, true)),
        arguments(
            new TypeHolder<Boolean>() {}.annotatedType(),
            "Nullable<Boolean>",
            true,
            exactly(null, false, true),
            exactly(null, false, true)),
        arguments(
            new TypeHolder<@NotNull List<@NotNull Boolean>>() {}.annotatedType(),
            "List<Boolean>",
            false,
            exactly(emptyList(), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull List<Boolean>>() {}.annotatedType(),
            "List<Nullable<Boolean>>",
            false,
            exactly(emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(
            new TypeHolder<List<@NotNull Boolean>>() {}.annotatedType(),
            "Nullable<List<Boolean>>",
            false,
            exactly(null, emptyList(), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<List<Boolean>>() {}.annotatedType(),
            "Nullable<List<Nullable<Boolean>>>",
            false,
            exactly(
                null, emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<@NotNull Boolean @NotNull []>() {}.annotatedType(),
            "Boolean[]",
            false,
            containsArrays(emptyList(), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<boolean @NotNull []>() {}.annotatedType(),
            "boolean[]",
            false,
            containsArrays(emptyList(), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<
                @InRange(min = 5, max = 6) @NotNull Integer @NotNull []>() {}.annotatedType(),
            "Integer[]",
            false,
            containsArrays(emptyList(), singletonList(5), singletonList(6)),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<@InRange(min = 5, max = 6) int[]>() {}.annotatedType(),
            "Nullable<int[]>",
            false,
            containsArrays(emptyList(), singletonList(5), singletonList(6)),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<@NotNull String @NotNull []>() {}.annotatedType(),
            "String[]",
            false,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<byte @NotNull []>() {}.annotatedType(),
            "byte[]",
            false,
            distinctElementsRatio(0.30),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<@NotNull TestEnumThree @NotNull []>() {}.annotatedType(),
            "Enum<TestEnumThree>[]",
            false,
            distinctElementsRatio(0.30),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<
                @NotNull ConstructorBasedBean @NotNull @WithLength(max = 10)
                    []>() {}.annotatedType(),
            "[Boolean, Nullable<String>, Integer] -> ConstructorBasedBean[]",
            false,
            distinctElementsRatio(0.30),
            distinctElementsRatio(0.30)),
        arguments(
            new TypeHolder<@NotNull Map<@NotNull String, @NotNull String>>() {}.annotatedType(),
            "Map<String, String>",
            false,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<Map<@NotNull String, @NotNull String>>() {}.annotatedType(),
            "Nullable<Map<String, String>>",
            false,
            distinctElementsRatio(0.46),
            distinctElementsRatio(0.48)),
        arguments(
            new TypeHolder<
                @WithSize(max = 3) @NotNull Map<
                    @NotNull Integer, @NotNull Integer>>() {}.annotatedType(),
            "Map<Integer, Integer>",
            false,
            // Half of all maps are empty, the other half is heavily biased towards special values.
            all(mapSizeInClosedRange(0, 3), distinctElementsRatio(0.19)),
            all(mapSizeInClosedRange(0, 3), manyDistinctElements())),
        arguments(
            new TypeHolder<@NotNull Map<@NotNull Boolean, @NotNull Boolean>>() {}.annotatedType(),
            "Map<Boolean, Boolean>",
            false,
            exactly(
                asMap(),
                asMap(false, false),
                asMap(false, true),
                asMap(true, false),
                asMap(true, true)),
            exactly(
                asMap(),
                asMap(false, false),
                asMap(false, true),
                asMap(true, false),
                asMap(true, true),
                asMap(false, false, true, false),
                asMap(false, false, true, true),
                asMap(false, true, true, false),
                asMap(false, true, true, true))),
        arguments(
            new ParameterHolder() {
              void singleParam(byte parameter) {}
            }.annotatedType(),
            "Byte",
            true,
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(
                expectedNumberOfDistinctElements(1 << Byte.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((byte) 0, (byte) 1, Byte.MIN_VALUE, Byte.MAX_VALUE)),
            // With mutations, we expect to reach all possible bytes.
            exactly(rangeClosed(Byte.MIN_VALUE, Byte.MAX_VALUE).mapToObj(i -> (byte) i).toArray())),
        arguments(
            new ParameterHolder() {
              void singleParam(short parameter) {}
            }.annotatedType(),
            "Short",
            true,
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(
                expectedNumberOfDistinctElements(1 << Short.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((short) 0, (short) 1, Short.MIN_VALUE, Short.MAX_VALUE)),
            // The integral type mutator does not always return uniformly random values and the
            // random walk it uses is more likely to produce non-distinct elements, hence the test
            // only passes with ~90% of the optimal parameters.
            expectedNumberOfDistinctElements(
                1 << Short.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(
            new ParameterHolder() {
              void singleParam(int parameter) {}
            }.annotatedType(),
            "Integer",
            true,
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(
                expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(0, 1, Integer.MIN_VALUE, Integer.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(
            new TypeHolder<@NotNull LocalDate>() {}.annotatedType(),
            "LocalDate",
            true,
            // We set the ratio relatively low because the long mutator is biased towards special
            // values.
            distinctElementsRatio(0.15),
            distinctElementsRatio(0.15)),
        arguments(
            new TypeHolder<@NotNull LocalDateTime>() {}.annotatedType(),
            "LocalDateTime",
            true,
            // We set the ratio relatively low because the long mutator is biased towards special
            // values.
            distinctElementsRatio(0.15),
            distinctElementsRatio(0.15)),
        arguments(
            new TypeHolder<@NotNull ZonedDateTime>() {}.annotatedType(),
            "ZonedDateTime",
            true,
            // We set the ratio relatively low because the long mutator is biased towards special
            // values.
            distinctElementsRatio(0.15),
            distinctElementsRatio(0.15)),
        arguments(
            new TypeHolder<@NotNull LocalTime>() {}.annotatedType(),
            "LocalTime",
            true,
            // We set the ratio relatively low because the long mutator is biased towards special
            // values.
            distinctElementsRatio(0.15),
            distinctElementsRatio(0.15)),
        arguments(
            new TypeHolder<@NotNull @InRange(min = 0) Long>() {}.annotatedType(),
            "Long",
            true,
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(
                expectedNumberOfDistinctElements(1L << Long.SIZE - 1, boundHits(NUM_INITS, 0.2)),
                contains(0L, 1L, Long.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE - 1, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(
            new TypeHolder<
                @NotNull @InRange(max = Integer.MIN_VALUE + 5) Integer>() {}.annotatedType(),
            "Integer",
            true,
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray()),
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray())),
        arguments(
            new TypeHolder<TestEnumTwo>() {}.annotatedType(),
            "Nullable<Enum<TestEnumTwo>>",
            true,
            exactly(null, TestEnumTwo.A, TestEnumTwo.B),
            exactly(null, TestEnumTwo.A, TestEnumTwo.B)),
        arguments(
            new TypeHolder<TestEnumThree>() {}.annotatedType(),
            "Nullable<Enum<TestEnumThree>>",
            true,
            exactly(null, TestEnumThree.A, TestEnumThree.B, TestEnumThree.C),
            exactly(null, TestEnumThree.A, TestEnumThree.B, TestEnumThree.C)),
        arguments(
            new TypeHolder<@NotNull @FloatInRange(min = 0f) Float>() {}.annotatedType(),
            "Float",
            true,
            all(
                distinctElementsRatio(0.45),
                doesNotContain(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, -Float.MIN_VALUE),
                contains(
                    Float.NaN,
                    Float.POSITIVE_INFINITY,
                    Float.MAX_VALUE,
                    Float.MIN_VALUE,
                    0.0f,
                    -0.0f)),
            all(
                distinctElementsRatio(0.75),
                doesNotContain(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, -Float.MIN_VALUE))),
        arguments(
            new TypeHolder<@NotNull Float>() {}.annotatedType(),
            "Float",
            true,
            all(
                distinctElementsRatio(0.45),
                contains(
                    Float.NaN,
                    Float.NEGATIVE_INFINITY,
                    Float.POSITIVE_INFINITY,
                    -Float.MAX_VALUE,
                    Float.MAX_VALUE,
                    -Float.MIN_VALUE,
                    Float.MIN_VALUE,
                    0.0f,
                    -0.0f)),
            distinctElementsRatio(0.76)),
        arguments(
            new TypeHolder<
                @NotNull @FloatInRange(min = -1.0f, max = 1.0f, allowNaN = false)
                Float>() {}.annotatedType(),
            "Float",
            true,
            all(
                distinctElementsRatio(0.45),
                doesNotContain(
                    Float.NaN,
                    -Float.MAX_VALUE,
                    Float.MAX_VALUE,
                    Float.NEGATIVE_INFINITY,
                    Float.POSITIVE_INFINITY),
                contains(-Float.MIN_VALUE, Float.MIN_VALUE, 0.0f, -0.0f)),
            all(
                distinctElementsRatio(0.525),
                doesNotContain(
                    Float.NaN,
                    -Float.MAX_VALUE,
                    Float.MAX_VALUE,
                    Float.NEGATIVE_INFINITY,
                    Float.POSITIVE_INFINITY),
                contains(-Float.MIN_VALUE, Float.MIN_VALUE, 0.0f, -0.0f))),
        arguments(
            new TypeHolder<@NotNull Double>() {}.annotatedType(),
            "Double",
            true,
            all(
                distinctElementsRatio(0.45),
                contains(Double.NaN, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY)),
            distinctElementsRatio(0.75)),
        arguments(
            new TypeHolder<
                @NotNull @DoubleInRange(min = -1.0, max = 1.0, allowNaN = false)
                Double>() {}.annotatedType(),
            "Double",
            true,
            all(distinctElementsRatio(0.45), doesNotContain(Double.NaN)),
            all(distinctElementsRatio(0.55), doesNotContain(Double.NaN))),
        arguments(
            new TypeHolder<@NotNull FuzzedDataProvider>() {}.annotatedType(),
            "FuzzedDataProvider",
            false,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<@NotNull SimpleRecord>() {}.annotatedType(),
            "[Integer, Boolean] -> SimpleRecord",
            true,
            contains(new SimpleRecord(0, false)),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull RepeatedRecord>() {}.annotatedType(),
            "[Nullable<[Integer, Boolean] -> SimpleRecord>, Nullable<[Integer, Boolean] ->"
                + " SimpleRecord>] -> RepeatedRecord",
            true,
            distinctElementsRatio(0.49),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull LinkedListNode>() {}.annotatedType(),
            "[Nullable<[Integer, Boolean] -> SimpleRecord>, Nullable<RecursionBreaking((cycle) ->"
                + " LinkedListNode)>] -> LinkedListNode",
            false,
            // Low due to recursion breaking initializing nested records to null.
            distinctElementsRatio(0.23),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull SetterBasedBeanWithParent>() {}.annotatedType(),
            "[Nullable<String>, Integer, Boolean, Long] -> SetterBasedBeanWithParent",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull LinkedListBean>() {}.annotatedType(),
            "[Nullable<RecursionBreaking((cycle) -> LinkedListBean)>, Integer] -> LinkedListBean",
            false,
            // Low due to recursion breaking initializing nested structs to null.
            distinctElementsRatio(0.22),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull ImmutableBuilder>() {}.annotatedType(),
            "[Boolean, Integer] -> ImmutableBuilder",
            true,
            // Low due to int and boolean fields having very few common values during init.
            distinctElementsRatio(0.23),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull ConstructorBasedBean>() {}.annotatedType(),
            "[Boolean, Nullable<String>, Integer] -> ConstructorBasedBean",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull OnlyConstructorBean>() {}.annotatedType(),
            "[Nullable<String>, Nullable<List<Nullable<Integer>>>, Boolean] -> OnlyConstructorBean",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull List<OnlyConstructorBean>>() {}.annotatedType(),
            "List<Nullable<[Nullable<String>, Nullable<List<Nullable<Integer>>>, Boolean] ->"
                + " OnlyConstructorBean>>",
            false,
            distinctElementsRatio(0.4),
            distinctElementsRatio(0.4)),
        arguments(
            new TypeHolder<SuperBuilderTarget>() {}.annotatedType(),
            "Nullable<[[Nullable<String>] -> SuperBuilderTargetBuilder] -> SuperBuilderTarget>",
            false,
            distinctElementsRatio(0.4),
            distinctElementsRatio(0.4)),
        arguments(
            new TypeHolder<Sealed>() {}.annotatedType(),
            "Nullable<([Boolean] -> A1 | ([Boolean] -> B1 | [Boolean] -> B2) | ([Boolean] -> C1 |"
                + " [Integer] -> C2))>",
            true,
            contains(
                null,
                new Sealed.A.A1(false),
                new Sealed.B.B1(false),
                new Sealed.B.B2(false),
                new Sealed.C.C1(false),
                new Sealed.C.C2(0)),
            contains(
                null,
                new Sealed.A.A1(false),
                new Sealed.B.B1(false),
                new Sealed.B.B2(false),
                new Sealed.C.C1(false),
                new Sealed.C.C2(0),
                new Sealed.A.A1(true),
                new Sealed.B.B1(true),
                new Sealed.B.B2(true),
                new Sealed.C.C1(true),
                new Sealed.C.C2(1))));
  }

  public static Stream<Arguments> protoStressTestCases() {
    return Stream.of(
        arguments(
            new TypeHolder<@NotNull OptionalPrimitiveField3>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>} -> Message",
            true,
            exactly(
                OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build()),
            exactly(
                OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build())),
        arguments(
            new TypeHolder<@NotNull RepeatedRecursiveMessageField3>() {}.annotatedType(),
            "{Builder.Boolean, WithoutInit(Builder via List<(cycle) -> Message>)} -> Message",
            false,
            // The message field is recursive and thus not initialized.
            exactly(
                RepeatedRecursiveMessageField3.getDefaultInstance(),
                RepeatedRecursiveMessageField3.newBuilder().setSomeField(true).build()),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull IntegralField3>() {}.annotatedType(),
            "{Builder.Integer} -> Message",
            true,
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(
                expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(
                    IntegralField3.newBuilder().build(),
                    IntegralField3.newBuilder().setSomeField(1).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MIN_VALUE).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MAX_VALUE).build())),
            // Our mutations return uniformly random elements in ~3/8 of all cases.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 3 / 8)),
        arguments(
            new TypeHolder<@NotNull RepeatedIntegralField3>() {}.annotatedType(),
            "{Builder via List<Integer>} -> Message",
            false,
            contains(
                RepeatedIntegralField3.getDefaultInstance(),
                RepeatedIntegralField3.newBuilder().addSomeField(0).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(1).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MAX_VALUE).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MIN_VALUE).build()),
            // TODO: This ratio is on the lower end, most likely because of the strong bias towards
            //  special values combined with the small initial size of the list. When we improve the
            //  list mutator, this may be increased.
            distinctElementsRatio(0.25)),
        arguments(
            new TypeHolder<@NotNull BytesField3>() {}.annotatedType(),
            "{Builder.byte[] -> ByteString} -> Message",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull StringField3>() {}.annotatedType(),
            "{Builder.String} -> Message",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull EnumField3>() {}.annotatedType(),
            "{Builder.Enum<TestEnum>} -> Message",
            true,
            exactly(
                EnumField3.getDefaultInstance(),
                EnumField3.newBuilder().setSomeField(TestEnum.VAL2).build()),
            exactly(
                EnumField3.getDefaultInstance(),
                EnumField3.newBuilder().setSomeField(TestEnum.VAL2).build())),
        arguments(
            new TypeHolder<@NotNull EnumFieldRepeated3>() {}.annotatedType(),
            "{Builder via List<Enum<TestEnumRepeated>>} -> Message",
            false,
            exactly(
                EnumFieldRepeated3.getDefaultInstance(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.UNASSIGNED).build(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.VAL1).build(),
                EnumFieldRepeated3.newBuilder().addSomeField(TestEnumRepeated.VAL2).build()),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull MapField3>() {}.annotatedType(),
            "{Builder.Map<Integer, String>} -> Message",
            false,
            distinctElementsRatio(0.46),
            manyDistinctElements()),
        arguments(
            new TypeHolder<@NotNull MessageMapField3>() {}.annotatedType(),
            "{Builder.Map<String, {Builder.Map<Integer, String>} -> Message>} -> Message",
            false,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.45)),
        arguments(
            new TypeHolder<@NotNull DoubleField3>() {}.annotatedType(),
            "{Builder.Double} -> Message",
            true,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.7)),
        arguments(
            new TypeHolder<@NotNull RepeatedDoubleField3>() {}.annotatedType(),
            "{Builder via List<Double>} -> Message",
            false,
            distinctElementsRatio(0.2),
            distinctElementsRatio(0.9)),
        arguments(
            new TypeHolder<@NotNull FloatField3>() {}.annotatedType(),
            "{Builder.Float} -> Message",
            true,
            distinctElementsRatio(0.45),
            distinctElementsRatio(0.7)),
        arguments(
            new TypeHolder<@NotNull RepeatedFloatField3>() {}.annotatedType(),
            "{Builder via List<Float>} -> Message",
            false,
            distinctElementsRatio(0.20),
            distinctElementsRatio(0.9),
            emptyList()),
        arguments(
            new TypeHolder<@NotNull TestProtobuf>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>, Builder.Nullable<Integer>, Builder.Nullable<Integer>,"
                + " Builder.Nullable<Long>, Builder.Nullable<Long>, Builder.Nullable<Float>,"
                + " Builder.Nullable<Double>, Builder.Nullable<String>,"
                + " Builder.Nullable<Enum<Enum>>,"
                + " WithoutInit(Builder.Nullable<{Builder.Nullable<Integer>, Builder via"
                + " List<Integer>, WithoutInit(Builder.Nullable<(cycle) -> Message>)} -> Message>),"
                + " Builder via List<Boolean>, Builder via List<Integer>, Builder via"
                + " List<Integer>, Builder via List<Long>, Builder via List<Long>, Builder via"
                + " List<Float>, Builder via List<Double>, Builder via List<String>, Builder via"
                + " List<Enum<Enum>>, WithoutInit(Builder via List<(cycle) -> Message>),"
                + " Builder.Map<Integer, Integer>, Builder.Nullable<FixedValue(OnlyLabel)>,"
                + " Builder.Nullable<{<empty>} -> Message>, Builder.Nullable<Integer> |"
                + " Builder.Nullable<Long> | Builder.Nullable<Integer>} -> Message",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<
                @NotNull
                @WithDefaultInstance(
                    "com.code_intelligence.jazzer.mutation.mutator.StressTest#getTestProtobufDefaultInstance")
                Message>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>, Builder.Nullable<Integer>, Builder.Nullable<Integer>,"
                + " Builder.Nullable<Long>, Builder.Nullable<Long>, Builder.Nullable<Float>,"
                + " Builder.Nullable<Double>, Builder.Nullable<String>,"
                + " Builder.Nullable<Enum<Enum>>,"
                + " WithoutInit(Builder.Nullable<{Builder.Nullable<Integer>, Builder via"
                + " List<Integer>, WithoutInit(Builder.Nullable<(cycle) -> Message>)} -> Message>),"
                + " Builder via List<Boolean>, Builder via List<Integer>, Builder via"
                + " List<Integer>, Builder via List<Long>, Builder via List<Long>, Builder via"
                + " List<Float>, Builder via List<Double>, Builder via List<String>, Builder via"
                + " List<Enum<Enum>>, WithoutInit(Builder via List<(cycle) -> Message>),"
                + " Builder.Map<Integer, Integer>, Builder.Nullable<FixedValue(OnlyLabel)>,"
                + " Builder.Nullable<{<empty>} -> Message>, Builder.Nullable<Integer> |"
                + " Builder.Nullable<Long> | Builder.Nullable<Integer>} -> Message",
            false,
            manyDistinctElements(),
            manyDistinctElements()),
        arguments(
            new TypeHolder<
                @NotNull @AnySource({PrimitiveField3.class, MessageField3.class})
                AnyField3>() {}.annotatedType(),
            "{Builder.Nullable<Builder.{Builder.Boolean} -> Message |"
                + " Builder.{Builder.Nullable<(cycle) -> Message>} -> Message -> Message>} ->"
                + " Message",
            true,
            exactly(
                AnyField3.getDefaultInstance(),
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
                        Any.pack(
                            MessageField3.newBuilder()
                                .setMessageField(PrimitiveField3.getDefaultInstance())
                                .build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(
                        Any.pack(
                            MessageField3.newBuilder()
                                .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                                .build()))
                    .build()),
            exactly(
                AnyField3.getDefaultInstance(),
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
                        Any.pack(
                            MessageField3.newBuilder()
                                .setMessageField(PrimitiveField3.getDefaultInstance())
                                .build()))
                    .build(),
                AnyField3.newBuilder()
                    .setSomeField(
                        Any.pack(
                            MessageField3.newBuilder()
                                .setMessageField(PrimitiveField3.newBuilder().setSomeField(true))
                                .build()))
                    .build())),
        arguments(
            new TypeHolder<@NotNull SingleOptionOneOfField3>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>} -> Message",
            true,
            exactly(
                SingleOptionOneOfField3.getDefaultInstance(),
                SingleOptionOneOfField3.newBuilder().setBoolField(false).build(),
                SingleOptionOneOfField3.newBuilder().setBoolField(true).build()),
            exactly(
                SingleOptionOneOfField3.getDefaultInstance(),
                SingleOptionOneOfField3.newBuilder().setBoolField(false).build(),
                SingleOptionOneOfField3.newBuilder().setBoolField(true).build())));
  }

  private static CloseableConsumer all(CloseableConsumer... checks) {
    return new CloseableConsumer() {
      @Override
      public void close() throws Exception {
        for (CloseableConsumer check : checks) {
          check.close();
        }
      }

      @Override
      public void accept(Object value) {
        for (CloseableConsumer check : checks) {
          check.accept(value);
        }
      }
    };
  }

  private static CloseableConsumer manyDistinctElements() {
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
    @SuppressWarnings("UnnecessaryLocalVariable")
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    return almostCertainLowerBound;
  }

  /**
   * Asserts that a given list contains at least as many distinct elements as can be expected when
   * picking {@code picks} out of {@code domainSize} elements uniformly at random.
   */
  private static CloseableConsumer expectedNumberOfDistinctElements(long domainSize, int picks) {
    // https://www.randomservices.org/random/urn/Birthday.html#mom2
    double expectedValue = domainSize * (1 - pow(1 - 1.0 / domainSize, picks));
    double variance =
        domainSize * (domainSize - 1) * pow(1 - 2.0 / domainSize, picks)
            + domainSize * pow(1 - 1.0 / domainSize, picks)
            - domainSize * domainSize * pow(1 - 1.0 / domainSize, 2 * picks);
    double standardDeviation = sqrt(variance);
    // Allow missing the expected value by two standard deviations. For a normal distribution,
    // this would correspond to 95% of all cases.
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    HashSet<Integer> hashes = new HashSet<>();
    return new CloseableConsumer() {
      @Override
      public void accept(Object value) {
        hashes.add(Objects.hashCode(value));
      }

      @Override
      public void close() {
        assertWithMessage(
                "V=distinct elements among %s picked out of %s\nE[V]=%s\nσ[V]=%s",
                picks, domainSize, expectedValue, standardDeviation)
            .that(hashes.size())
            .isAtLeast(almostCertainLowerBound);
      }
    };
  }

  private static CloseableConsumer distinctElementsRatio(double ratio) {
    require(ratio > 0);
    require(ratio <= 1);
    List<Integer> hashes = new ArrayList<>();
    return new CloseableConsumer() {
      @Override
      public void accept(Object value) {
        hashes.add(Objects.hashCode(value));
      }

      @Override
      public void close() {
        assertThat(new HashSet<>(hashes).size() / (double) hashes.size()).isAtLeast(ratio);
      }
    };
  }

  private static CloseableConsumer exactly(Object... expected) {
    return containsInternal(true, expected);
  }

  private static CloseableConsumer exactlyArrays(Object... expected) {
    return containsArraysInternal(true, expected);
  }

  private static CloseableConsumer contains(Object... expected) {
    return containsInternal(false, expected);
  }

  private static <T> CloseableConsumer containsArrays(T... expected) {
    return containsArraysInternal(false, expected);
  }

  private static CloseableConsumer containsInternal(boolean exactly, Object... expected) {
    Map<Object, Boolean> sawValue =
        stream(expected)
            .collect(
                toMap(
                    value -> value,
                    value -> false,
                    (a, b) -> {
                      throw new IllegalStateException("Duplicate value " + a);
                    },
                    HashMap::new));
    return new CloseableConsumer() {
      @Override
      public void accept(Object value) {
        if (exactly) {
          assertThat(value).isIn(sawValue.keySet());
        }
        sawValue.put(value, true);
      }

      @Override
      public void close() {
        assertThat(sawValue.entrySet().stream().filter(e -> !e.getValue()).collect(toList()))
            .isEmpty();
      }
    };
  }

  private static <T, K> CloseableConsumer containsArraysInternal(boolean exactly, T... expected) {
    Map<List<K>, Boolean> sawValue =
        (Map<List<K>, Boolean>)
            stream(expected)
                .collect(
                    toMap(
                        value -> value,
                        value -> false,
                        (a, b) -> {
                          throw new IllegalStateException("Duplicate value " + a);
                        },
                        HashMap::new));
    return new CloseableConsumer() {
      @Override
      public void accept(Object value) {
        List<K> list = new ArrayList<>();
        if (value != null) {
          for (int i = 0; i < Array.getLength(value); i++) {
            list.add((K) Array.get(value, i));
          }
        }

        if (exactly) {
          assertThat(list).isIn(sawValue.keySet());
        }
        sawValue.put(list, true);
      }

      @Override
      public void close() {
        assertThat(sawValue.entrySet().stream().filter(e -> !e.getValue()).collect(toList()))
            .isEmpty();
      }
    };
  }

  private static CloseableConsumer doesNotContain(Object... expected) {
    return new CloseableConsumer() {
      @Override
      public void accept(Object value) {
        assertThat(value).isNotIn(asList(expected));
      }

      @Override
      public void close() {}
    };
  }

  private static CloseableConsumer mapSizeInClosedRange(int min, int max) {
    return new CloseableConsumer() {
      @Override
      public void accept(Object map) {
        if (map instanceof Map) {
          assertThat(((Map<?, ?>) map).size()).isAtLeast(min);
          assertThat(((Map<?, ?>) map).size()).isAtMost(max);
        } else {
          throw new IllegalArgumentException(
              "Expected a list of maps, got list of" + map.getClass().getName());
        }
      }

      @Override
      public void close() {}
    };
  }

  interface CloseableConsumer extends AutoCloseable, Consumer<Object> {}

  @SuppressWarnings("rawtypes")
  @ParameterizedTest(name = "{index} {0}, {1}")
  @MethodSource({"stressTestCases", "protoStressTestCases"})
  void genericMutatorStressTest(
      AnnotatedType type,
      String mutatorTree,
      boolean hasFixedSize,
      CloseableConsumer checkInitValues,
      CloseableConsumer checkMutatedValues)
      throws Exception {
    validateAnnotationUsage(type);
    ExtendedMutatorFactory factory = Mutators.newFactory();

    SerializingMutator mutator = factory.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo(mutatorTree);
    assertThat(mutator.hasFixedSize()).isEqualTo(hasFixedSize);

    // Even with a fallback to mutating map values when no new key can be constructed, the map
    // {false: true, true: false} will not change its equality class when the fallback picks both
    // values to mutate.
    boolean mayPerformNoopMutations =
        mutatorTree.contains("FixedValue(") || mutatorTree.contains("Map<Boolean, Boolean>");

    PseudoRandom rng = anyPseudoRandom();

    for (int i = 0; i < NUM_INITS; i++) {
      Object value = mutator.init(rng);

      // For proto messages, each float field with value -0.0f, and double field with value -0.0
      // will be converted to 0.0f and 0.0, respectively.
      Object fixedValue = fixFloatingPointsForProtos(value);
      testReadWriteRoundtrip(mutator, fixedValue);
      testReadWriteExclusiveRoundtrip(mutator, fixedValue);

      checkInitValues.accept(value);
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
            assertNotEqualMutatorValues(detachedOldValue, value);
          }
        }

        checkMutatedValues.accept(value);

        // For proto messages, each float field with value -0.0f, and double field with value -0.0
        // will be converted to 0.0f and 0.0, respectively. This is because the values -0f and 0f
        // and their double counterparts are serialized as default values (0f, and 0.0), which is
        // relevant for mutation and the round trip tests. This means that the protos with float or
        // double fields that equal to negative zero, will start mutation from positive zeros, and
        // cause the assertion above to fail from time to time. To avoid this, we convert all
        // negative zeros to positive zeros for float and double proto fields.
        value = fixFloatingPointsForProtos(value);
        testReadWriteRoundtrip(mutator, value);
        testReadWriteExclusiveRoundtrip(mutator, value);

        // Verify that the initial value was isolated and not mutated as well.
        testReadWriteRoundtrip(mutator, fixedValue);
        testReadWriteExclusiveRoundtrip(mutator, fixedValue);
      }

      // Cleanup factory cache after mutations to reduce memory consumption.
      factory.getCache().clear();
    }

    checkInitValues.close();
    checkMutatedValues.close();
  }

  private static <T> void testReadWriteExclusiveRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.writeExclusive(value, out);
    T newValue = serializer.readExclusive(new ByteArrayInputStream(out.toByteArray()));
    assertEqualMutatorValues(newValue, value);
  }

  private static <T> void testReadWriteRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.write(value, new DataOutputStream(out));
    T newValue =
        serializer.read(
            new DataInputStream(extendWithZeros(new ByteArrayInputStream(out.toByteArray()))));
    assertEqualMutatorValues(newValue, value);
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
    walkFields(
        builder,
        oldValue -> {
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

  // Provide dedicated equals method to compare mutator values and handle
  // FuzzedDataProviderImpl checks without an equals method in that class.
  private static void assertEqualMutatorValues(Object actual, Object expected) {
    if (actual instanceof FuzzedDataProviderImpl && expected instanceof FuzzedDataProviderImpl) {
      assertThat(((FuzzedDataProviderImpl) actual).getJavaData())
          .isEqualTo(((FuzzedDataProviderImpl) expected).getJavaData());
    } else {
      assertThat(actual).isEqualTo(expected);
    }
  }

  private static void assertNotEqualMutatorValues(Object actual, Object expected) {
    if (actual instanceof FuzzedDataProviderImpl && expected instanceof FuzzedDataProviderImpl) {
      assertThat(((FuzzedDataProviderImpl) actual).getJavaData())
          .isNotEqualTo(((FuzzedDataProviderImpl) expected).getJavaData());
    } else {
      assertThat(actual).isNotEqualTo(expected);
    }
  }
}
