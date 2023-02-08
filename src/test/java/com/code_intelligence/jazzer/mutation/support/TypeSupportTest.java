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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.ParameterizedType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

class TypeSupportTest {
  @Test
  void testFillTypeVariablesRawType_oneVariable() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull List>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType());
    AnnotatedParameterizedType expected =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull List<@NotNull String>>() {
        }.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual.getType()).isEqualTo(expected.getType());
    assertThat(expected.getType()).isEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(expected.getAnnotations());
    assertThat(expected.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(((ParameterizedType) actual.getType()).getActualTypeArguments())
        .isEqualTo(((ParameterizedType) expected.getType()).getActualTypeArguments());
    assertThat(((ParameterizedType) expected.getType()).getActualTypeArguments())
        .isEqualTo(((ParameterizedType) actual.getType()).getActualTypeArguments());
  }

  @Test
  // Java <= 11 does not implement AnnotatedType#equals.
  // https://github.com/openjdk/jdk/commit/ab0128ca51de59aaaa674654ca8d4e16b3b79965
  @EnabledForJreRange(min = JRE.JAVA_12)
  void testFillTypeVariablesAnnotatedType_oneVariable() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull List>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType());
    AnnotatedParameterizedType expected =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull List<@NotNull String>>() {
        }.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual).isEqualTo(expected);
    assertThat(expected).isEqualTo(actual);

    assertThat(actual.getType()).isEqualTo(expected.getType());
    assertThat(expected.getType()).isEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(expected.getAnnotations());
    assertThat(expected.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(actual.getAnnotatedActualTypeArguments())
        .isEqualTo(expected.getAnnotatedActualTypeArguments());
    assertThat(expected.getAnnotatedActualTypeArguments())
        .isEqualTo(actual.getAnnotatedActualTypeArguments());
  }

  @Test
  void testFillTypeVariablesRawType_oneVariable_differentType() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull List>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType());
    AnnotatedParameterizedType differentParameterAnnotation =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull List<@NotNull Boolean>>() {
        }.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual.getType()).isNotEqualTo(differentParameterAnnotation.getType());
    assertThat(differentParameterAnnotation.getType()).isNotEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(differentParameterAnnotation.getAnnotations());
    assertThat(differentParameterAnnotation.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(((ParameterizedType) actual.getType()).getActualTypeArguments())
        .isNotEqualTo(
            ((ParameterizedType) differentParameterAnnotation.getType()).getActualTypeArguments());
    assertThat(
        ((ParameterizedType) differentParameterAnnotation.getType()).getActualTypeArguments())
        .isNotEqualTo(((ParameterizedType) actual.getType()).getActualTypeArguments());
  }

  @Test
  // Java <= 11 does not implement AnnotatedType#equals.
  // https://github.com/openjdk/jdk/commit/ab0128ca51de59aaaa674654ca8d4e16b3b79965
  @EnabledForJreRange(min = JRE.JAVA_12)
  void testFillTypeVariablesAnnotatedType_oneVariable_differentAnnotations() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull List>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType());
    AnnotatedParameterizedType differentParameterAnnotation =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull List<String>>() {}.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual).isNotEqualTo(differentParameterAnnotation);
    assertThat(differentParameterAnnotation).isNotEqualTo(actual);

    assertThat(actual.getType()).isEqualTo(differentParameterAnnotation.getType());
    assertThat(differentParameterAnnotation.getType()).isEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(differentParameterAnnotation.getAnnotations());
    assertThat(differentParameterAnnotation.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(actual.getAnnotatedActualTypeArguments())
        .isNotEqualTo(differentParameterAnnotation.getAnnotatedActualTypeArguments());
    assertThat(differentParameterAnnotation.getAnnotatedActualTypeArguments())
        .isNotEqualTo(actual.getAnnotatedActualTypeArguments());
  }

  @Test
  void testFillTypeVariablesRawType_twoVariables() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull Map>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType(),
            new TypeHolder<byte[]>() {}.annotatedType());
    AnnotatedParameterizedType expected =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull Map<@NotNull String, byte[]>>() {
        }.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual.getType()).isEqualTo(expected.getType());
    assertThat(expected.getType()).isEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(expected.getAnnotations());
    assertThat(expected.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(((ParameterizedType) actual.getType()).getActualTypeArguments())
        .isEqualTo(((ParameterizedType) expected.getType()).getActualTypeArguments());
    assertThat(((ParameterizedType) expected.getType()).getActualTypeArguments())
        .isEqualTo(((ParameterizedType) actual.getType()).getActualTypeArguments());
  }

  @Test
  // Java <= 11 does not implement AnnotatedType#equals.
  // https://github.com/openjdk/jdk/commit/ab0128ca51de59aaaa674654ca8d4e16b3b79965
  @EnabledForJreRange(min = JRE.JAVA_12)
  void testFillTypeVariablesAnnotatedType_twoVariables() {
    AnnotatedParameterizedType actual =
        withTypeArguments(new TypeHolder<@NotNull Map>() {}.annotatedType(),
            new TypeHolder<@NotNull String>() {}.annotatedType(),
            new TypeHolder<byte[]>() {}.annotatedType());
    AnnotatedParameterizedType expected =
        (AnnotatedParameterizedType) new TypeHolder<@NotNull Map<@NotNull String, byte[]>>() {
        }.annotatedType();

    // Test both equals implementations as we implement them ourselves.
    assertThat(actual).isEqualTo(expected);
    assertThat(expected).isEqualTo(actual);

    assertThat(actual.getType()).isEqualTo(expected.getType());
    assertThat(expected.getType()).isEqualTo(actual.getType());

    assertThat(actual.getAnnotations()).isEqualTo(expected.getAnnotations());
    assertThat(expected.getAnnotations()).isEqualTo(actual.getAnnotations());

    assertThat(actual.getAnnotatedActualTypeArguments())
        .isEqualTo(expected.getAnnotatedActualTypeArguments());
    assertThat(expected.getAnnotatedActualTypeArguments())
        .isEqualTo(actual.getAnnotatedActualTypeArguments());
  }

  @Test
  void testFillTypeVariables_failures() {
    assertThrows(IllegalArgumentException.class,
        () -> withTypeArguments(new TypeHolder<List>() {}.annotatedType()));
    assertThrows(IllegalArgumentException.class, () -> withTypeArguments(new TypeHolder<List<?>>() {
    }.annotatedType(), asAnnotatedType(String.class)));
  }

  @Test
  void testAsSubclassOrEmpty() {
    assertThat(asSubclassOrEmpty(asAnnotatedType(String.class), String.class))
        .hasValue(String.class);
    assertThat(asSubclassOrEmpty(asAnnotatedType(String.class), CharSequence.class))
        .hasValue(String.class);
    assertThat(asSubclassOrEmpty(asAnnotatedType(CharSequence.class), String.class)).isEmpty();
    assertThat(asSubclassOrEmpty(new TypeHolder<List<String>>() {
    }.annotatedType(), List.class)).isEmpty();
  }
}
