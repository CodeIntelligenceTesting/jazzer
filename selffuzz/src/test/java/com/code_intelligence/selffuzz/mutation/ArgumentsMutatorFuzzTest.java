/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.selffuzz.mutation;

import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import com.code_intelligence.jazzer.protobuf.Proto3;
import com.code_intelligence.selffuzz.jazzer.mutation.ArgumentsMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.Mutators;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ArgumentsMutatorFuzzTest {
  static List<Method> methods = getSelfFuzzTestMethods();
  static List<ArgumentsMutator> mutators =
      methods.stream()
          .map(
              m ->
                  ArgumentsMutator.forMethod(Mutators.newFactory(), m)
                      .orElseThrow(() -> new IllegalArgumentException("Invalid method: " + m)))
          .collect(Collectors.toList());

  static {
    System.out.println("Found " + methods.size() + " @SelfFuzzTest methods.");
    for (Method method : methods) {
      System.out.println(" - " + method);
    }
    assertThat(methods).isNotEmpty();
  }

  /**
   * Second-order fuzzing of the mutation framework. Runs all fuzz tests marked by @SelfFuzzTest. We
   * use FuzzedDataProvider to force the top-level fuzzer to not use the mutation framework, for
   * easier debugging.
   */
  @FuzzTest
  void allTests(FuzzedDataProvider data) throws Throwable {
    int index = data.consumeInt(0, methods.size() - 1);
    Method method = methods.get(index);
    ArgumentsMutator mutator = mutators.get(index);

    long seed = data.consumeLong();
    byte[] input = data.consumeRemainingAsBytes();

    try {
      mutator.init(seed);
      ByteArrayOutputStream initedOut = new ByteArrayOutputStream();
      mutator.write(new DataOutputStream(initedOut));
      InputStream inited = new ByteArrayInputStream(initedOut.toByteArray());

      mutator.read(new ByteArrayInputStream(input));
      mutator.invoke(this, true);

      mutator.mutate(seed);
      ByteArrayOutputStream mutatedOut = new ByteArrayOutputStream();
      mutator.write(new DataOutputStream(mutatedOut));
      InputStream mutated = new ByteArrayInputStream(mutatedOut.toByteArray());

      mutator.crossOver(mutated, inited, seed);
    } catch (Exception e) {
      throw new RuntimeException("In method: " + method, e);
    }
  }

  @SelfFuzzTest
  void fuzzStrings(
      @NotNull @WithUtf8Length(min = 5, max = 7) String s0,
      @NotNull String s1,
      @NotNull @WithUtf8Length(min = 10, max = 20) String s2) {}

  @SelfFuzzTest // BUG: null pointer exception
  void fuzzListOfMaps(Map<String, Integer> nullableMap) {}

  @SelfFuzzTest
  void fuzzListOfLists(List<@NotNull List<String>> nullableMap, List<List<Integer>> nullableList) {}

  @SelfFuzzTest
  void fuzzPPrimitiveArrays(
      int @WithLength(max = 10) [] a0, boolean[] a2, int @WithLength(max = 8193) [] a3) {}

  @SelfFuzzTest
  void fuzzBean(@NotNull ConstructorPropertiesAnnotatedBean bean, BeanWithParent beanWithParent) {}

  @SelfFuzzTest
  void fuzzListOfBeans(@WithSize(max = 4) List<BeanWithParent> beanWithParent) {}

  @SelfFuzzTest
  void fuzzListOfListOfBeans(
      @WithSize(max = 4) List<@WithSize(max = 4) List<BeanWithParent>> beanWithParent) {}

  @SelfFuzzTest
  void fuzzTime(LocalDate date, LocalTime time, LocalDateTime dateTime) {}

  @SelfFuzzTest
  void fuzz_Arrays(
      List<int @WithLength(max = 10) []> listOfIntArrays,
      byte[] @WithLength(max = 11) [] byteArrays) {}

  public static class EmptyArgs {
    EmptyArgs() {}
  }

  @SelfFuzzTest
  void fuzz_EmptyArgs(@NotNull EmptyArgs emptyArgs) {}

  @SelfFuzzTest
  void fuzz_ImmutableBean(@NotNull ImmutableBean b) {}

  @SelfFuzzTest
  void fuzzPrimitives(
      Integer i0,
      int i1,
      Boolean b0,
      boolean b1,
      Double d0,
      double d1,
      Float f0,
      float f1,
      Long l0,
      long l1,
      Byte by0,
      byte by1,
      Short s0,
      short s1) {}

  @SelfFuzzTest
  void fuzzPrimitivesNotNull(
      @NotNull Integer i0,
      int i1,
      @NotNull Boolean b0,
      boolean b1,
      @NotNull Double d0,
      double d1,
      @NotNull Float f0,
      float f1,
      @NotNull Long l0,
      long l1,
      @NotNull Byte by0,
      byte by1,
      @NotNull Short s0,
      short s1) {}

  @SelfFuzzTest
  void fuzzPrimitiveArrays(
      Integer @WithLength(max = 3) [] i0,
      int[] i1,
      Boolean @WithLength(max = 3) [] b0,
      boolean[] b1,
      Double @WithLength(max = 3) [] d0,
      double[] d1,
      Float @WithLength(max = 3) [] f0,
      float[] f1,
      Long @WithLength(max = 3) [] l0,
      long[] l1,
      Byte @WithLength(max = 3) [] by0,
      byte[] by1,
      Short @WithLength(max = 3) [] s0,
      short[] s1) {}

  enum MyEnum {
    A,
    B,
    C,
    D,
    E,
    F,
    G
  }

  @SelfFuzzTest
  void fuzz_Enums(MyEnum e0, MyEnum e1, MyEnum e2) {}

  @SelfFuzzTest
  void fuzz_ProtoBufs(
      // com.google.protobuf.StringValue v0, // BUG: makes maxIncreaseSize negative in
      // LibProtobufMutator.mutate
      com.google.protobuf.Int32Value v1,
      com.google.protobuf.BoolValue v2,
      com.google.protobuf.UInt64Value v3,
      com.google.protobuf.FloatValue v4,
      com.google.protobuf.DoubleValue v5,
      // com.google.protobuf.BytesValue v6, // BUG: makes maxIncreaseSize negative in
      // LibProtobufMutator.mutate
      com.google.protobuf.Int64Value v7) {
    if (v7 != null) {
      assertThat(v7.getValue()).isAtLeast(Long.MIN_VALUE);
      assertThat(v7.getValue()).isAtMost(Long.MAX_VALUE);
    }
  }

  @SelfFuzzTest
  void fuzz_ProtoBufsNotNull(
      // @NotNull com.google.protobuf.StringValue v0, // BUG: makes maxIncreaseSize negative in
      // LibProtobufMutator.mutate
      @NotNull com.google.protobuf.Int32Value v1,
      @NotNull com.google.protobuf.BoolValue v2,
      @NotNull com.google.protobuf.UInt64Value v3,
      @NotNull com.google.protobuf.FloatValue v4,
      @NotNull com.google.protobuf.DoubleValue v5,
      // @NotNull com.google.protobuf.BytesValue v6, // BUG: makes maxIncreaseSize negative in
      // LibProtobufMutator.mutate
      @NotNull com.google.protobuf.Int64Value v7) {
    if (v7 != null) {
      assertThat(v7.getValue()).isAtLeast(Long.MIN_VALUE);
      assertThat(v7.getValue()).isAtMost(Long.MAX_VALUE);
    }
  }

  // BUG: makes maxIncreaseSize negative in LibProtobufMutator.mutate
  // @SelfFuzzTest
  // public static void fuzz_TestProtobuf(TestProtobuf o1) {}

  @SelfFuzzTest
  void fuzz_MapField3(Proto3.MapField3 o1) {}

  // BUG: causes java.lang.IllegalArgumentException: argument type mismatch
  //      no problem when testing the two types separately
  //  @SelfFuzzTest
  //  public static void fuzz_MutuallyReferringProtobufs(
  //      Proto2.TestProtobuf o1, Proto2.TestSubProtobuf o2) {}

  /**
   * @return all methods in this class annotated by @SelfFuzzTest. If any of those methods are
   *     annotated by @Solo, only those are returned.
   */
  private static List<Method> getSelfFuzzTestMethods() {
    return Arrays.stream(MethodHandles.lookup().lookupClass().getDeclaredMethods())
        .filter(m -> m.isAnnotationPresent(SelfFuzzTest.class))
        .collect(
            Collectors.collectingAndThen(
                Collectors.partitioningBy(m -> m.isAnnotationPresent(Solo.class)),
                // Return @Solo methods if any, otherwise all @SelfFuzzTest methods.
                map -> map.get(true).isEmpty() ? map.get(false) : map.get(true)));
  }

  /** Every method (public or private) annotated by @SelfFuzzTest will be fuzzed. */
  @Retention(RetentionPolicy.RUNTIME)
  public @interface SelfFuzzTest {}

  /** When debugging, annotate @SelfFuzzTest fuzz tests by @Solo to only run those. */
  @Retention(RetentionPolicy.RUNTIME)
  public @interface Solo {}
}
