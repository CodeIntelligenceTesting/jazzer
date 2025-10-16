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

import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypeIfParameterized;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static com.code_intelligence.jazzer.mutation.utils.PropertyConstraint.DECLARATION;
import static com.code_intelligence.jazzer.mutation.utils.PropertyConstraint.RECURSIVE;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.ValuePool;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ValuePoolsTest {

  /* Dummy fuzz test method to add to MutatorRuntime. */
  public void dummyFuzzTestMethod() {}

  private static final ValuePoolRegistry valuePools;

  static {
    try {
      valuePools = new ValuePoolRegistry(ValuePoolsTest.class.getMethod("dummyFuzzTestMethod"));
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }

  public static Stream<?> myPool() {
    return Stream.of("value1", "value2", "value3");
  }

  public static Stream<?> myPool2() {
    return Stream.of("value1", "value2", "value3", "value4");
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
            withValuePoolImplementation(new String[] {"myPool2"}, 0.3));
    double p = valuePools.extractFirstProbability(type);
    assertThat(p).isEqualTo(0.2);
  }

  @Test
  void testExtractRawValues_OneAnnotation() {
    AnnotatedType type = new TypeHolder<@ValuePool("myPool") String>() {}.annotatedType();
    Optional<Stream<?>> elements = valuePools.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3");
  }

  @Test
  void testExtractProviderStreams_JoinStreamsInOneProvider() {
    AnnotatedType type =
        new TypeHolder<@ValuePool({"myPool", "myPool2"}) String>() {}.annotatedType();
    Optional<Stream<?>> elements = valuePools.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinTwoFromOne() {
    AnnotatedType type =
        new TypeHolder<@ValuePool({"myPool", "myPool2"}) String>() {}.annotatedType();
    Optional<Stream<?>> elements = valuePools.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinFromTwoSeparateAnnotations() {
    AnnotatedType type =
        withExtraAnnotations(
            new TypeHolder<@ValuePool("myPool2") String>() {}.annotatedType(),
            withValuePoolImplementation(new String[] {"myPool"}, 5));
    Optional<Stream<?>> elements = valuePools.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
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

  private static ValuePool[] getValuePoolAnnotations(AnnotatedType type) {
    return Arrays.stream(type.getAnnotations())
        .filter(annotation -> annotation instanceof ValuePool)
        .toArray(ValuePool[]::new);
  }

  private static Stream<String> extractValuesFromValuePools(AnnotatedType type) {
    return Arrays.stream(getValuePoolAnnotations(type)).flatMap(v -> Arrays.stream(v.value()));
  }

  public static ValuePool withValuePoolImplementation(String[] value, double p) {
    return withValuePoolImplementation(value, p, RECURSIVE);
  }

  public static ValuePool withValuePoolImplementation(String[] value, double p, String constraint) {
    return new ValuePool() {
      @Override
      public String[] value() {
        return value;
      }

      @Override
      public double p() {
        return p;
      }

      @Override
      public String constraint() {
        return constraint;
      }

      @Override
      public Class<? extends Annotation> annotationType() {
        return ValuePool.class;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof ValuePool)) {
          return false;
        }
        ValuePool other = (ValuePool) o;
        return Arrays.equals(this.value(), other.value())
            && this.p() == other.p()
            && this.constraint().equals(other.constraint());
      }

      @Override
      public int hashCode() {
        int hash = 0;
        hash += Arrays.hashCode(value()) * 127;
        hash += Double.hashCode(p()) * 31 * 127;
        hash += constraint().hashCode() * 127;
        return hash;
      }

      @Override
      public String toString() {
        return "@"
            + ValuePool.class.getName()
            + "(value={"
            + String.join(", ", value())
            + "}, p="
            + p()
            + ", constraint="
            + constraint()
            + ")";
      }
    };
  }
}
