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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.GlobTestSupport.mockSourceDirectory;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypeIfParameterized;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static com.code_intelligence.jazzer.mutation.utils.PropertyConstraint.DECLARATION;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.annotation.ValuePool;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ValuePoolsTest {

  /* Dummy fuzz test method to add to MutatorRuntime. */
  public void dummyFuzzTestMethod() {}

  private static final ValuePoolRegistry valuePools;

  private static Method fuzzTestMethod;

  static {
    try {
      fuzzTestMethod = ValuePoolsTest.class.getMethod("dummyFuzzTestMethod");
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
    valuePools = new ValuePoolRegistry(fuzzTestMethod);
  }

  public static Stream<?> myPool() {
    return Stream.of("value1", "value2", "value3");
  }

  public static Stream<?> myPool2() {
    return Stream.of("value1", "value2", "value3", "value4");
  }

  private static Stream<?> myPrivatePool() {
    return Stream.of("private!");
  }

  public static Stream<Integer> poolOfInts() {
    return Stream.of(1, 2, 3);
  }

  public static List<Integer> listSupplier() {
    return Arrays.asList(1, 2, 3);
  }

  public static Stream<?> badPool(int arg) {
    return Stream.of(1, 2, 3);
  }

  public static Stream<?> emptyPool() {
    return Stream.empty();
  }

  private static int sideEffectCounter = 0;

  static Stream<?> poolWithSideEffect() {
    sideEffectCounter++;
    return Stream.of("only once");
  }

  @Test
  void testExtractFirstProbability_Default() {
    AnnotatedType type = new TypeHolder<@ValuePool("myPool") String>() {}.annotatedType();
    double p = valuePools.extractFirstProbability(type);
    assertThat(p).isEqualTo(0.1);
  }

  @Test
  void testExtractFirstProbability_OneUserDefined() {
    AnnotatedType type =
        new TypeHolder<@ValuePool(value = "myPool2", p = 0.2) String>() {}.annotatedType();
    double p = valuePools.extractFirstProbability(type);
    assertThat(p).isEqualTo(0.2);
  }

  @Test
  void testExtractFirstProbability_TwoWithLastUsed() {
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<@ValuePool(value = "myPool", p = 0.2) String>() {}.annotatedType(),
            new ValuePoolBuilder().value("myPool2").p(0.3).build());
    double p = valuePools.extractFirstProbability(type);
    assertThat(p).isEqualTo(0.2);
  }

  @Test
  void testExtractFirstMaxMutations_Default() {
    AnnotatedType type = new TypeHolder<@ValuePool("myPool") String>() {}.annotatedType();
    int maxMutations = valuePools.extractFirstMaxMutations(type);
    assertThat(maxMutations).isEqualTo(1);
  }

  @Test
  void testExtractFirstMaxMutations_OneUserDefined() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(value = "myPool2", maxMutations = 10) String>() {}.annotatedType();
    int maxMutations = valuePools.extractFirstMaxMutations(type);
    assertThat(maxMutations).isEqualTo(10);
  }

  @Test
  void testExtractMaxMutations_TwoWithLastUsed() {
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<
                @ValuePool(value = "myPool", maxMutations = 2) String>() {}.annotatedType(),
            new ValuePoolBuilder().value("myPool2").maxMutations(10).build());
    int maxMutations = valuePools.extractFirstMaxMutations(type);
    assertThat(maxMutations).isEqualTo(2);
  }

  @Test
  void testExtractFirstMaxMutations_Negative() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(value = "myPool2", maxMutations = -1) String>() {}.annotatedType();
    assertThat(
            assertThrows(
                IllegalArgumentException.class, () -> valuePools.extractFirstMaxMutations(type)))
        .hasMessageThat()
        .contains("@ValuePool maxMutations must be >= 0");
  }

  @Test
  void testExtractRawValues_OneAnnotation() {
    AnnotatedType type = new TypeHolder<@ValuePool("myPool") String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("value1", "value2", "value3");
  }

  @Test
  void testExtractProviderStreams_JoinStreamsInOneProvider() {
    AnnotatedType type =
        new TypeHolder<@ValuePool({"myPool", "myPool2"}) String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinTwoFromOne() {
    AnnotatedType type =
        new TypeHolder<@ValuePool({"myPool", "myPool2"}) String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinFromTwoSeparateAnnotations() {
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<@ValuePool("myPool2") String>() {}.annotatedType(),
            new ValuePoolBuilder().value("myPool").build());
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_PrivatePool() {
    AnnotatedType type = new TypeHolder<@ValuePool("myPrivatePool") String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("private!");
  }

  @Test
  void testExtractRawValues_SupplierInAnotherClass() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool("com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#myPool")
            String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements)
        .containsExactly("external1", "external2", "external3", 1232187321, -182371);
  }

  @Test
  void testExtractRawValues_SupplierInAnotherClassNotPresent() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#nonexistent")
            String>() {}.annotatedType();
    assertThrows(
        IllegalArgumentException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_EmptyAnnotationIsNoop() {
    AnnotatedType type = new TypeHolder<@ValuePool(p = 0.2) String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isEmpty();
  }

  @Test
  void testExtractRawValues_ThrowWhenSupplierReturnsNoValues() {
    AnnotatedType type = new TypeHolder<@ValuePool("emptyPool") String>() {}.annotatedType();
    assertThat(
            assertThrows(
                IllegalStateException.class,
                () -> valuePools.extractUserValues(type).collect(Collectors.toList())))
        .hasMessageThat()
        .contains("returned no values");
  }

  @Test
  void testExtractRawValues_InvalidMethodReference_MissingClass() {
    AnnotatedType type = new TypeHolder<@ValuePool("#myPool") String>() {}.annotatedType();
    assertThrows(
        IllegalArgumentException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_InvalidMethodReference_MissingMethod() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool("com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#")
            String>() {}.annotatedType();
    assertThrows(
        IllegalArgumentException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_InvalidMethodReference_MultipleHashes() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#myPool#x")
            String>() {}.annotatedType();
    assertThrows(
        IllegalArgumentException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_InvalidSupplier_ReturnsList() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#listSupplier")
            String>() {}.annotatedType();
    assertThrows(
        IllegalStateException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_InvalidLocalSupplier_ReturnsList() {
    AnnotatedType type = new TypeHolder<@ValuePool("listSupplier") String>() {}.annotatedType();
    assertThrows(
        IllegalStateException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_BadPool() {
    AnnotatedType type = new TypeHolder<@ValuePool("badPool") String>() {}.annotatedType();
    assertThrows(
        IllegalArgumentException.class,
        () -> valuePools.extractUserValues(type).collect(Collectors.toList()));
  }

  @Test
  void testExtractRawValues_StreamOfConcreteTypeSupplier() {
    AnnotatedType type = new TypeHolder<@ValuePool("poolOfInts") String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly(1, 2, 3);
  }

  @Test
  void testExtractRawValues_OverloadedSupplier() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport#myPrivatePoolWithOverload")
            String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements)
        .containsExactly("external1", "external2", "external3", 1232187321, -182371);
  }

  @Test
  void testExtractRawValues_SupplierInNestedClass() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport$Nested#myPool")
            String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("nested");
  }

  @Test
  void testExtractRawValues_MergeSuppliersFromDifferentClasses() {
    AnnotatedType type =
        new TypeHolder<
            @ValuePool(
                value = {
                  "com.code_intelligence.jazzer.mutation.support.ValuePoolsTestSupport$Nested#myPool",
                  "myPool"
                })
            String>() {}.annotatedType();
    List<?> elements = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements).isNotEmpty();
    assertThat(elements).containsExactly("nested", "value1", "value2", "value3");
  }

  @Test
  void testExtractRawValues_SuppliersCalledOncePerRegistry() {
    // Each supplier method is called once per fuzz test method (i.e. per ValuePoolRegistry)
    ValuePoolRegistry valuePools = new ValuePoolRegistry(fuzzTestMethod);
    sideEffectCounter = 0;
    AnnotatedType type =
        new TypeHolder<@ValuePool("poolWithSideEffect") String>() {}.annotatedType();
    List<?> elements1 = valuePools.extractUserValues(type).collect(Collectors.toList());
    List<?> elements2 = valuePools.extractUserValues(type).collect(Collectors.toList());
    List<?> elements3 = valuePools.extractUserValues(type).collect(Collectors.toList());
    assertThat(elements1).containsExactly("only once");
    assertThat(elements2).containsExactly("only once");
    assertThat(elements3).containsExactly("only once");
    assertThat(sideEffectCounter).isEqualTo(1);
  }

  @Test
  void testExtractRawValues_SupplierNameInvariance() {
    // Each supplier method is called once per fuzz test method (i.e. per ValuePoolRegistry)
    ValuePoolRegistry valuePools = new ValuePoolRegistry(fuzzTestMethod);
    sideEffectCounter = 0;
    AnnotatedType type1 =
        new TypeHolder<@ValuePool("poolWithSideEffect") String>() {}.annotatedType();
    AnnotatedType type2 =
        new TypeHolder<
            @ValuePool(
                "com.code_intelligence.jazzer.mutation.support.ValuePoolsTest#poolWithSideEffect")
            String>() {}.annotatedType();
    List<?> elements1 = valuePools.extractUserValues(type1).collect(Collectors.toList());
    List<?> elements2 = valuePools.extractUserValues(type2).collect(Collectors.toList());
    assertThat(elements1).containsExactly("only once");
    assertThat(elements2).containsExactly("only once");
    assertThat(sideEffectCounter).isEqualTo(1);
  }

  @Test
  void changeParametersOnly() {
    AnnotatedType sourceType =
        new TypeHolder<
            @ValuePool(value = "list", p = 1.0, maxMutations = 0) List<
                @ValuePool(p = 0.9, maxMutations = 100) String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();
    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    assertThat(extractValuesFromValuePools(propagatedType)).containsExactly("list");
    assertThat(0.9).isEqualTo(valuePools.extractFirstProbability(propagatedType));
    assertThat(100).isEqualTo(valuePools.extractFirstMaxMutations(propagatedType));
  }

  @Test
  void propagateAndJoinRecursiveValuePools() {
    AnnotatedType sourceType =
        new TypeHolder<
            @ValuePool(value = "list", p = 1.0) List<
                @ValuePool(value = "string", p = 0.9) String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    assertThat(extractValuesFromValuePools(propagatedType)).containsExactly("list", "string");
    assertThat(0.9).isEqualTo(valuePools.extractFirstProbability(propagatedType));
  }

  @Test
  void dontPropagateNonRecursiveValuePool() {
    AnnotatedType sourceType =
        new TypeHolder<
            @ValuePool(value = "list", p = 1.0, constraint = DECLARATION) List<
                @ValuePool(value = "string", p = 0.9) String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    assertThat(extractValuesFromValuePools(propagatedType)).containsExactly("string");
    assertThat(0.9).isEqualTo(valuePools.extractFirstProbability(propagatedType));
  }

  @Test
  void testExtractRawValues_Files_NonRecursive(@TempDir Path tempDir) throws IOException {
    mockSourceDirectory(tempDir);
    String glob = tempDir + "/*.txt";
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder().files(glob).build());

    List<String> elements =
        valuePools
            .extractUserValues(type)
            .map(value -> new String((byte[]) value, StandardCharsets.UTF_8))
            .collect(Collectors.toList());

    assertThat(elements).containsExactly("a.txt", "c.zip.txt");
  }

  @Test
  void testExtractRawValues_Files_Recursive(@TempDir Path tempDir) throws IOException {
    mockSourceDirectory(tempDir);
    String glob = tempDir + "/**/*.txt";
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder().files(glob).build());

    List<String> elements =
        valuePools
            .extractUserValues(type)
            .map(value -> new String((byte[]) value, StandardCharsets.UTF_8))
            .collect(Collectors.toList());

    assertThat(elements)
        .containsExactly(
            "sub/b.txt",
            "sub/deep/c.txt",
            "sub/deep/corpus/d.txt",
            "sub/deeper/than/mah.txt",
            "test/c/d/bar.txt");
  }

  @Test
  void testExtractRawValues_Files_RelativePatternInsideBrackets(@TempDir Path tempDir)
      throws IOException {
    mockSourceDirectory(tempDir);
    String glob = "{" + "**/*.txt}";
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder().files(glob).build());

    // Need to create ValuePoolRegistry with tempDir as working directory
    ValuePoolRegistry valuePools = new ValuePoolRegistry(fuzzTestMethod, tempDir);

    List<String> elements =
        valuePools
            .extractUserValues(type)
            .map(value -> new String((byte[]) value, StandardCharsets.UTF_8))
            .collect(Collectors.toList());

    assertThat(elements)
        .containsExactly(
            "sub/b.txt",
            "sub/deep/c.txt",
            "sub/deep/corpus/d.txt",
            "sub/deeper/than/mah.txt",
            "test/c/d/bar.txt");
  }

  @Test
  void testExtractRawValues_Files_OverlappingPatternsAreDeduped(@TempDir Path tempDir)
      throws IOException {
    mockSourceDirectory(tempDir);

    String recursiveGlob = tempDir + "/**.txt";
    String directGlob = tempDir + "/*.txt";
    String relativeRecursiveGlob = "**.txt";

    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder().files(recursiveGlob, directGlob, relativeRecursiveGlob).build());

    ValuePoolRegistry valuePools;
    try {
      valuePools =
          new ValuePoolRegistry(ValuePoolsTest.class.getMethod("dummyFuzzTestMethod"), tempDir);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }

    List<String> elements =
        valuePools
            .extractUserValues(type)
            .map(value -> new String((byte[]) value, StandardCharsets.UTF_8))
            .collect(Collectors.toList());

    assertThat(elements)
        .containsExactly(
            "a.txt",
            "c.zip.txt",
            "sub/b.txt",
            "sub/deep/c.txt",
            "sub/deep/corpus/d.txt",
            "sub/deeper/than/mah.txt",
            "test/c/d/bar.txt");
  }

  @Test
  void testExtractRawValues_Files_GlobsWithMethodSources(@TempDir Path tempDir) throws IOException {
    mockSourceDirectory(tempDir);

    String recursiveGlob = tempDir + "/**.txt";
    String directGlob = tempDir + "/*.txt";
    String relativeRecursiveGlob = "**.txt";

    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder()
                .value("myPool")
                .files(recursiveGlob, directGlob, relativeRecursiveGlob)
                .build());

    // Need to create ValuePoolRegistry with tempDir as "working directory"
    ValuePoolRegistry valuePools;
    try {
      valuePools =
          new ValuePoolRegistry(ValuePoolsTest.class.getMethod("dummyFuzzTestMethod"), tempDir);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }

    List<?> elements =
        valuePools
            .extractUserValues(type)
            // if byte[], convert to string
            .map(
                value -> {
                  if (value instanceof byte[]) {
                    return new String((byte[]) value, StandardCharsets.UTF_8);
                  } else {
                    return value;
                  }
                })
            .collect(Collectors.toList());

    assertThat(elements)
        .containsExactly(
            // method sources
            "value1",
            "value2",
            "value3",
            // globs
            "a.txt",
            "c.zip.txt",
            "sub/b.txt",
            "sub/deep/c.txt",
            "sub/deep/corpus/d.txt",
            "sub/deeper/than/mah.txt",
            "test/c/d/bar.txt");
  }

  @Test
  void testExtractRawValues_Files_PatternsWithGlobSymbols(@TempDir Path tempDir)
      throws IOException {
    mockSourceDirectory(tempDir);

    String recursiveGlob = tempDir + "/weird/\\[\\]\\{\\}.glob";

    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<byte[]>() {}.annotatedType(),
            new ValuePoolBuilder().files(recursiveGlob).build());

    List<String> elements =
        valuePools
            .extractUserValues(type)
            .map(value -> new String((byte[]) value, StandardCharsets.UTF_8))
            .collect(Collectors.toList());

    assertThat(elements).containsExactly("weird/[]{}.glob");
  }

  private static ValuePool[] getValuePoolAnnotations(AnnotatedType type) {
    return Arrays.stream(type.getAnnotations())
        .filter(annotation -> annotation instanceof ValuePool)
        .toArray(ValuePool[]::new);
  }

  private static Stream<String> extractValuesFromValuePools(AnnotatedType type) {
    return Arrays.stream(getValuePoolAnnotations(type)).flatMap(v -> Arrays.stream(v.value()));
  }

  private static class ValuePoolBuilder {
    private String[] value;
    private String[] files;
    private double p;
    private int maxMutations;
    private String constraint;

    public ValuePoolBuilder() {
      try {
        value = (String[]) getDefault("value");
        files = (String[]) getDefault("files");
        p = (double) getDefault("p");
        maxMutations = (int) getDefault("maxMutations");
        constraint = (String) getDefault("constraint");
      } catch (NoSuchMethodException e) {
        throw new RuntimeException("Could not load ValuePool defaults", e);
      }
    }

    private Object getDefault(String methodName) throws NoSuchMethodException {
      return ValuePool.class.getDeclaredMethod(methodName).getDefaultValue();
    }

    public ValuePoolBuilder value(String... values) {
      this.value = values;
      return this;
    }

    public ValuePoolBuilder files(String... files) {
      this.files = files;
      return this;
    }

    public ValuePoolBuilder p(double p) {
      this.p = p;
      return this;
    }

    public ValuePoolBuilder maxMutations(int maxMutations) {
      this.maxMutations = maxMutations;
      return this;
    }

    public ValuePoolBuilder constraint(String constraint) {
      this.constraint = constraint;
      return this;
    }

    public ValuePool build() {
      final String[] value = this.value;
      final double p = this.p;
      final int maxMutations = this.maxMutations;
      final String constraint = this.constraint;

      return new ValuePool() {
        @Override
        public Class<? extends Annotation> annotationType() {
          return ValuePool.class;
        }

        @Override
        public String[] value() {
          return value;
        }

        @Override
        public String[] files() {
          return files;
        }

        @Override
        public double p() {
          return p;
        }

        @Override
        public int maxMutations() {
          return maxMutations;
        }

        @Override
        public String constraint() {
          return constraint;
        }

        @Override
        public boolean equals(Object o) {
          if (!(o instanceof ValuePool)) {
            return false;
          }
          ValuePool other = (ValuePool) o;
          return Arrays.equals(this.value(), other.value())
              && Arrays.equals(this.files(), other.files())
              && this.p() == other.p()
              && this.maxMutations() == other.maxMutations()
              && this.constraint().equals(other.constraint());
        }

        @Override
        public int hashCode() {
          return Objects.hash(
              Arrays.hashCode(value()),
              Arrays.hashCode(files()),
              p(),
              maxMutations(),
              constraint());
        }

        @Override
        public String toString() {
          return "@"
              + ValuePool.class.getName()
              + "(value={"
              + String.join(", ", value())
              + "}, files="
              + String.join(", ", files())
              + "}, p="
              + p()
              + ", maxMutations="
              + maxMutations()
              + ", constraint="
              + constraint()
              + ")";
        }
      };
    }
  }
}
