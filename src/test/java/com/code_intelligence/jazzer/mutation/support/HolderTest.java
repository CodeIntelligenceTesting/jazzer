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

import com.code_intelligence.jazzer.mutation.support.TestSupport.ParameterHolder;
import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import org.junit.jupiter.api.Test;

class HolderTest {
  @Test
  void testTypeHolder_rawType() {
    Type type = new TypeHolder<List<String>>() {}.type();
    assertThat(type).isInstanceOf(ParameterizedType.class);

    ParameterizedType parameterizedType = (ParameterizedType) type;
    assertThat(parameterizedType.getRawType()).isEqualTo(List.class);
    assertThat(parameterizedType.getActualTypeArguments()).asList().containsExactly(String.class);
  }

  @Test
  void testTypeHolder_annotatedType() {
    AnnotatedType type = new TypeHolder<@Foo List<@Bar String>>() {}.annotatedType();
    assertThat(type).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType listType = (AnnotatedParameterizedType) type;
    assertThat(listType.getType()).isInstanceOf(ParameterizedType.class);
    assertThat(((ParameterizedType) listType.getType()).getRawType()).isEqualTo(List.class);
    assertThat(listType.getAnnotations()).hasLength(1);
    assertThat(listType.getAnnotations()[0]).isInstanceOf(Foo.class);
    assertThat(listType.getAnnotatedActualTypeArguments()).hasLength(1);

    AnnotatedType stringType = listType.getAnnotatedActualTypeArguments()[0];
    assertThat(stringType.getType()).isEqualTo(String.class);
    assertThat(stringType.getAnnotations()).hasLength(1);
    assertThat(stringType.getAnnotations()[0]).isInstanceOf(Bar.class);
  }

  @Test
  void testParameterHolder_rawType() {
    Type type =
        new ParameterHolder() {
          void singleParam(List<String> parameter) {}
        }.type();
    assertThat(type).isInstanceOf(ParameterizedType.class);

    ParameterizedType parameterizedType = (ParameterizedType) type;
    assertThat(parameterizedType.getRawType()).isEqualTo(List.class);
    assertThat(parameterizedType.getActualTypeArguments()).asList().containsExactly(String.class);
  }

  @Test
  void testParameterHolder_annotatedType() {
    AnnotatedType type =
        new ParameterHolder() {
          void singleParam(@ParameterAnnotation @Foo List<@Bar String> parameter) {}
        }.annotatedType();
    assertThat(type).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType listType = (AnnotatedParameterizedType) type;
    assertThat(listType.getType()).isInstanceOf(ParameterizedType.class);
    assertThat(((ParameterizedType) listType.getType()).getRawType()).isEqualTo(List.class);
    assertThat(listType.getAnnotations()).hasLength(1);
    assertThat(listType.getAnnotations()[0]).isInstanceOf(Foo.class);
    assertThat(listType.getAnnotatedActualTypeArguments()).hasLength(1);

    AnnotatedType stringType = listType.getAnnotatedActualTypeArguments()[0];
    assertThat(stringType.getType()).isEqualTo(String.class);
    assertThat(stringType.getAnnotations()).hasLength(1);
    assertThat(stringType.getAnnotations()[0]).isInstanceOf(Bar.class);
  }

  @Test
  void testParameterHolder_parameterAnnotations() {
    Annotation[] annotations =
        new ParameterHolder() {
          void singleParam(@ParameterAnnotation @Foo List<@Bar String> parameter) {}
        }.parameterAnnotations();
    assertThat(annotations).hasLength(1);
    assertThat(annotations[0]).isInstanceOf(ParameterAnnotation.class);
  }

  @Target(ElementType.TYPE_USE)
  @Retention(RetentionPolicy.RUNTIME)
  private @interface Foo {}

  @Target(ElementType.TYPE_USE)
  @Retention(RetentionPolicy.RUNTIME)
  private @interface Bar {}

  @Target(ElementType.PARAMETER)
  @Retention(RetentionPolicy.RUNTIME)
  private @interface ParameterAnnotation {}
}
