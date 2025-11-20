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

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.AnnotatedWildcardType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ParameterizedTypeSupportTest {
  @Test
  void resolveParameterizedType() throws NoSuchFieldException {
    class Generic<T> {
      public List<T> field;
    }
    AnnotatedType annotatedType = Generic.class.getDeclaredField("field").getAnnotatedType();
    AnnotatedParameterizedType classType =
        (AnnotatedParameterizedType) new TypeHolder<Generic<@NotNull String>>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(Generic.class, classType, annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType parameterType = (AnnotatedParameterizedType) resolved;
    assertThat(((ParameterizedType) parameterType.getType()).getRawType()).isEqualTo(List.class);
    AnnotatedType elementType = parameterType.getAnnotatedActualTypeArguments()[0];
    assertThat(elementType.getType()).isEqualTo(String.class);
    assertThat(
            TypeSupport.annotatedTypeEquals(
                classType.getAnnotatedActualTypeArguments()[0], elementType))
        .isTrue();
  }

  @Test
  void resolveArrayType() throws NoSuchFieldException {
    class Generic<T> {
      public T[] field;
    }
    AnnotatedType annotatedType = Generic.class.getDeclaredField("field").getAnnotatedType();
    AnnotatedParameterizedType classType =
        (AnnotatedParameterizedType) new TypeHolder<Generic<@NotNull String>>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(Generic.class, classType, annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedArrayType.class);

    AnnotatedArrayType arrayType = (AnnotatedArrayType) resolved;
    assertThat(arrayType.getType().getTypeName()).isEqualTo(String[].class.getTypeName());
    AnnotatedType componentType = arrayType.getAnnotatedGenericComponentType();
    assertThat(componentType.getType()).isEqualTo(String.class);
    assertThat(
            TypeSupport.annotatedTypeEquals(
                classType.getAnnotatedActualTypeArguments()[0], componentType))
        .isTrue();
  }

  @Test
  void resolveWildcardType() throws NoSuchFieldException {
    class Generic<T> {
      public List<? extends T> field;
    }
    AnnotatedType annotatedType = Generic.class.getDeclaredField("field").getAnnotatedType();
    AnnotatedParameterizedType classType =
        (AnnotatedParameterizedType) new TypeHolder<Generic<@NotNull String>>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(Generic.class, classType, annotatedType);

    AnnotatedParameterizedType parameterType = (AnnotatedParameterizedType) resolved;
    assertThat(((ParameterizedType) parameterType.getType()).getRawType()).isEqualTo(List.class);

    AnnotatedType wildcardArgument = parameterType.getAnnotatedActualTypeArguments()[0];
    assertThat(wildcardArgument).isInstanceOf(AnnotatedWildcardType.class);

    AnnotatedWildcardType wildcardType = (AnnotatedWildcardType) wildcardArgument;
    AnnotatedType[] upperBounds = wildcardType.getAnnotatedUpperBounds();
    assertThat(upperBounds).hasLength(1);
    assertThat(upperBounds[0].getType()).isEqualTo(String.class);
    assertThat(
            TypeSupport.annotatedTypeEquals(
                classType.getAnnotatedActualTypeArguments()[0],
                wildcardType.getAnnotatedUpperBounds()[0]))
        .isTrue();
  }

  @Test
  void resolveParameterizedType_twoTypeArguments() throws NoSuchFieldException {
    class Generic<S, T> {
      public @NotNull Map<S, T> field;
    }
    AnnotatedType annotatedType = Generic.class.getDeclaredField("field").getAnnotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(
            Generic.class,
            new TypeHolder<Generic<@NotNull String, @NotNull Integer>>() {}.annotatedType(),
            annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedParameterizedType.class);
    AnnotatedParameterizedType annotatedParameterizedType = (AnnotatedParameterizedType) resolved;
    Type resolvedType = annotatedParameterizedType.getType();
    assertThat(resolvedType).isInstanceOf(ParameterizedType.class);
    ParameterizedType parameterizedType = (ParameterizedType) resolvedType;
    assertThat(parameterizedType.getRawType()).isEqualTo(Map.class);
    assertThat(parameterizedType.getActualTypeArguments()[0]).isEqualTo(String.class);
    assertThat(parameterizedType.getActualTypeArguments()[1]).isEqualTo(Integer.class);
  }

  @Test
  void resolveParameterizedTypeChildClass() throws NoSuchFieldException {
    class Base<T, U> {
      public Map<T, U> field;
    }
    class Child<U> extends Base<String, U> {}
    AnnotatedType annotatedType = Child.class.getField("field").getAnnotatedType();
    AnnotatedParameterizedType classType =
        (AnnotatedParameterizedType) new TypeHolder<Child<Integer>>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(Child.class, classType, annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType parameterType = (AnnotatedParameterizedType) resolved;
    assertThat(((ParameterizedType) parameterType.getType()).getRawType()).isEqualTo(Map.class);
    AnnotatedType[] elementTypes = parameterType.getAnnotatedActualTypeArguments();
    assertThat(elementTypes).hasLength(2);
    assertThat(elementTypes[0].getType()).isEqualTo(String.class);
    assertThat(
            TypeSupport.annotatedTypeEquals(
                classType.getAnnotatedActualTypeArguments()[0], elementTypes[1]))
        .isTrue();
  }

  @Test
  void resolveParameterizedType_multiLevelHierarchy() throws NoSuchFieldException {
    class Root<T> {
      public List<T> field;
    }
    class Middle<U> extends Root<List<U>> {}
    class Leaf<V> extends Middle<V> {}
    class Concrete extends Leaf<String> {}

    AnnotatedType annotatedType = Concrete.class.getField("field").getAnnotatedType();
    AnnotatedType classType = new TypeHolder<Concrete>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(Concrete.class, classType, annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType outerList = (AnnotatedParameterizedType) resolved;
    assertThat(((ParameterizedType) outerList.getType()).getRawType()).isEqualTo(List.class);
    AnnotatedType nestedListType = outerList.getAnnotatedActualTypeArguments()[0];
    assertThat(nestedListType).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType innerList = (AnnotatedParameterizedType) nestedListType;
    assertThat(((ParameterizedType) innerList.getType()).getRawType()).isEqualTo(List.class);
    AnnotatedType innerElement = innerList.getAnnotatedActualTypeArguments()[0];
    assertThat(innerElement.getType()).isEqualTo(String.class);
  }

  private interface LocalSupplier<T> {
    List<T> supply();
  }

  private interface AnnotatedSupplier<U> extends LocalSupplier<List<U>> {}

  @Test
  void resolveParameterizedType_interfaceHierarchy() throws NoSuchMethodException {
    AnnotatedType annotatedType = LocalSupplier.class.getMethod("supply").getAnnotatedReturnType();
    AnnotatedParameterizedType interfaceType =
        (AnnotatedParameterizedType)
            new TypeHolder<AnnotatedSupplier<@NotNull String>>() {}.annotatedType();
    AnnotatedType resolved =
        ParameterizedTypeSupport.resolveTypeArguments(
            AnnotatedSupplier.class, interfaceType, annotatedType);

    assertThat(resolved).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType outerList = (AnnotatedParameterizedType) resolved;
    assertThat(((ParameterizedType) outerList.getType()).getRawType()).isEqualTo(List.class);

    AnnotatedType nestedType = outerList.getAnnotatedActualTypeArguments()[0];
    assertThat(nestedType).isInstanceOf(AnnotatedParameterizedType.class);

    AnnotatedParameterizedType innerList = (AnnotatedParameterizedType) nestedType;
    assertThat(((ParameterizedType) innerList.getType()).getRawType()).isEqualTo(List.class);
    AnnotatedType terminalElement = innerList.getAnnotatedActualTypeArguments()[0];
    assertThat(
            TypeSupport.annotatedTypeEquals(
                interfaceType.getAnnotatedActualTypeArguments()[0], terminalElement))
        .isTrue();
  }
}
