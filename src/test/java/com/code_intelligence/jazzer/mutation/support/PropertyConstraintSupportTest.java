/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
