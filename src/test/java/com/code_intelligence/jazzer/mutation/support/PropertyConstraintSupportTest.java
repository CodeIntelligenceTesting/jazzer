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
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.Ascii;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

@SuppressWarnings("OptionalGetWithoutIsPresent")
public class PropertyConstraintSupportTest {
  @Test
  @EnabledForJreRange(min = JRE.JAVA_12)
  void doNotPropagateDeclarationConstraint() {
    AnnotatedType sourceType = new TypeHolder<@NotNull List<@Ascii String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    AnnotatedType expectedType = new TypeHolder<@Ascii String>() {}.annotatedType();
    assertThat(propagatedType).isEqualTo(expectedType);
  }

  @Test
  void propagateRecursiveConstraint() {
    AnnotatedType sourceType =
        new TypeHolder<
            @NotNull(constraint = PropertyConstraint.RECURSIVE) List<String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    AnnotatedType expectedType =
        new TypeHolder<
            @NotNull(constraint = PropertyConstraint.RECURSIVE) String>() {}.annotatedType();
    assertThat(propagatedType).isEqualTo(expectedType);
  }

  @Test
  void propagateRecursiveConstraintAndKeepExistingAnnotation() {
    AnnotatedType sourceType =
        new TypeHolder<
            @NotNull(constraint = PropertyConstraint.RECURSIVE) List<
                @Ascii String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    AnnotatedType expectedType =
        new TypeHolder<
            @Ascii @NotNull(constraint = PropertyConstraint.RECURSIVE) String>() {}.annotatedType();
    assertThat(propagatedType).isEqualTo(expectedType);
  }

  @Test
  void preferInnerConstraintToPropagatedOne() {
    AnnotatedType sourceType =
        new TypeHolder<
            @NotNull(constraint = PropertyConstraint.RECURSIVE) List<
                @NotNull String>>() {}.annotatedType();
    AnnotatedType targetType = parameterTypeIfParameterized(sourceType, List.class).get();

    AnnotatedType propagatedType = propagatePropertyConstraints(sourceType, targetType);

    assertThat(propagatedType).isEqualTo(targetType);
  }
}
