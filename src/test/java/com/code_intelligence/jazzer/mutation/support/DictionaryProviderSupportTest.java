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

import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.DictionaryProvider;
import com.code_intelligence.jazzer.mutation.runtime.MutationRuntime;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class DictionaryProviderSupportTest {

  /* Dummy fuzz test method to add to MutatorRuntime. */
  public void dummyFuzzTestMethod() {}

  static {
    try {
      MutationRuntime.fuzzTestMethod =
          DictionaryProviderSupportTest.class.getMethod("dummyFuzzTestMethod");
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }

  public static Stream<?> myProvider() {
    return Stream.of("value1", "value2", "value3");
  }

  public static Stream<?> myProvider2() {
    return Stream.of("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractFirstInvProbability_Default() {
    AnnotatedType type =
        new TypeHolder<@DictionaryProvider("myProvider") String>() {}.annotatedType();
    int pInv = DictionaryProviderSupport.extractFirstInvProbability(type);
    assertThat(pInv).isEqualTo(10);
  }

  @Test
  void testExtractFirstInvProbability_OneUserDefined() {
    AnnotatedType type =
        new TypeHolder<
            @DictionaryProvider(value = "myProvider2", pInv = 2) String>() {}.annotatedType();
    int pInv = DictionaryProviderSupport.extractFirstInvProbability(type);
    assertThat(pInv).isEqualTo(2);
  }

  @Test
  void testExtractFirstInvProbability_TwoWithLastUsed() {
    AnnotatedType type =
        TypeSupport.withExtraAnnotations(
            new TypeHolder<
                @DictionaryProvider(value = "myProvider", pInv = 2) String>() {}.annotatedType(),
            withDictionaryProviderImplementation(new String[] {"myProvider2"}, 3));
    int pInv = DictionaryProviderSupport.extractFirstInvProbability(type);
    assertThat(pInv).isEqualTo(2);
  }

  @Test
  void testExtractRawValues_OneAnnotation() {
    AnnotatedType type =
        new TypeHolder<@DictionaryProvider("myProvider") String>() {}.annotatedType();
    Optional<Stream<?>> elements = DictionaryProviderSupport.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3");
  }

  @Test
  void testExtractProviderStreams_JoinStreamsInOneProvider() {
    AnnotatedType type =
        new TypeHolder<
            @DictionaryProvider({"myProvider", "myProvider2"}) String>() {}.annotatedType();
    Optional<Stream<?>> elements = DictionaryProviderSupport.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinTwoFromOne() {
    AnnotatedType type =
        new TypeHolder<
            @DictionaryProvider({"myProvider", "myProvider2"}) String>() {}.annotatedType();
    Optional<Stream<?>> elements = DictionaryProviderSupport.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
  }

  @Test
  void testExtractRawValues_JoinFromTwoSeparateAnnotations() {
    AnnotatedType type =
        TypeSupport.withExtraAnnotations(
            new TypeHolder<@DictionaryProvider("myProvider2") String>() {}.annotatedType(),
            withDictionaryProviderImplementation(new String[] {"myProvider"}, 5));
    Optional<Stream<?>> elements = DictionaryProviderSupport.extractRawValues(type);
    assertThat(elements).isPresent();
    assertThat(elements.get()).containsExactly("value1", "value2", "value3", "value4");
  }

  private static DictionaryProvider withDictionaryProviderImplementation(String[] value, int pInv) {
    return withDictionaryProviderImplementation(value, pInv, PropertyConstraint.RECURSIVE);
  }

  private static DictionaryProvider withDictionaryProviderImplementation(
      String[] value, int pInv, String constraint) {
    return new DictionaryProvider() {
      @Override
      public String[] value() {
        return value;
      }

      @Override
      public int pInv() {
        return pInv;
      }

      @Override
      public String constraint() {
        return constraint;
      }

      @Override
      public Class<? extends Annotation> annotationType() {
        return DictionaryProvider.class;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof DictionaryProvider)) {
          return false;
        }
        DictionaryProvider other = (DictionaryProvider) o;
        return Arrays.equals(this.value(), other.value())
            && this.pInv() == other.pInv()
            && this.constraint().equals(other.constraint());
      }

      @Override
      public int hashCode() {
        int hash = 0;
        hash += Arrays.hashCode(value()) * 127;
        hash += pInv() * 31 * 127;
        hash += constraint().hashCode() * 127;
        return hash;
      }

      @Override
      public String toString() {
        return "@"
            + DictionaryProvider.class.getName()
            + "(value={"
            + String.join(", ", value())
            + "}, pInv="
            + pInv()
            + ", constraint="
            + constraint()
            + ")";
      }
    };
  }
}
