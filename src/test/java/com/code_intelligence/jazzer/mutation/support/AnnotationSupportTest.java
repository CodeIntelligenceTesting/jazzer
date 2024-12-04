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

import static com.code_intelligence.jazzer.mutation.support.AnnotationSupport.validateAnnotationUsage;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.Ascii;
import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.UrlSegment;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class AnnotationSupportTest {

  static Stream<Arguments> validateAnnotationUsageCases_ok() {
    return Stream.of(
        arguments(new TypeHolder<@WithSize(min = 10) List<Double>>() {}.annotatedType()),
        arguments(new TypeHolder<@NotNull @WithSize(min = 10) List<Double>>() {}.annotatedType()),
        arguments(new TypeHolder<Integer @NotNull @WithLength(min = 10) []>() {}.annotatedType()),
        arguments(new TypeHolder<@WithUtf8Length(min = 10) String>() {}.annotatedType()),
        arguments(new TypeHolder<@UrlSegment String>() {}.annotatedType()),
        arguments(
            new TypeHolder<
                @Ascii(constraint = PropertyConstraint.RECURSIVE) List<
                    String>>() {}.annotatedType()));
  }

  @ParameterizedTest
  @MethodSource("validateAnnotationUsageCases_ok")
  void testValidateAnnotationUsage_ok(AnnotatedType type) {
    validateAnnotationUsage(type);
  }

  static Stream<Arguments> validateAnnotationUsageCases_throw() {
    return Stream.of(
        // sizes/lengths
        arguments(new TypeHolder<@WithSize(min = -1) List<Double>>() {}.annotatedType()),
        arguments(new TypeHolder<@WithSize(min = 10, max = 9) List<Double>>() {}.annotatedType()),
        arguments(new TypeHolder<Double @WithLength(min = -1) []>() {}.annotatedType()),
        arguments(new TypeHolder<Double @WithLength(min = 10, max = 9) []>() {}.annotatedType()),
        arguments(new TypeHolder<@WithUtf8Length(min = -1) String>() {}.annotatedType()),
        arguments(new TypeHolder<@WithUtf8Length(min = 11, max = 0) String>() {}.annotatedType()),
        // ranges
        arguments(new TypeHolder<@InRange(min = -1, max = -2) Integer>() {}.annotatedType()),
        arguments(new TypeHolder<@FloatInRange(min = -1f, max = -2f) Float>() {}.annotatedType()),
        arguments(
            new TypeHolder<@DoubleInRange(min = -1.0, max = -2.0) Double>() {}.annotatedType()),
        // deep
        arguments(
            new TypeHolder<
                @NotNull @WithSize(min = 0, max = 10) List<
                        List<List<@WithSize(min = -1) List<Double>>>>
                    []>() {}.annotatedType()),
        // violations of @AppliesTo
        arguments(new TypeHolder<@WithSize(min = 10) String>() {}.annotatedType()),
        arguments(new TypeHolder<@WithLength(min = 10) List<String>>() {}.annotatedType()),
        arguments(new TypeHolder<@InRange(min = 10) List<String>>() {}.annotatedType()),
        arguments(new TypeHolder<String @InRange(min = 10) []>() {}.annotatedType()),
        arguments(new TypeHolder<@UrlSegment Integer>() {}.annotatedType()),
        arguments(new TypeHolder<@UrlSegment List<String>>() {}.annotatedType()),
        // deep
        arguments(
            new TypeHolder<
                @NotNull @WithSize(min = 0, max = 10) List<
                        List<List<@WithLength(min = 0, max = 1) List<Double>>>>
                    []>() {}.annotatedType()));
  }

  @ParameterizedTest
  @MethodSource("validateAnnotationUsageCases_throw")
  void testValidateAnnotationUsage_throw(AnnotatedType type) {
    assertThrows(IllegalArgumentException.class, () -> validateAnnotationUsage(type));
  }
}
