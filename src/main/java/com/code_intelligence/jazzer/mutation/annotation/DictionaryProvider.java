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

package com.code_intelligence.jazzer.mutation.annotation;

import static com.code_intelligence.jazzer.mutation.utils.PropertyConstraint.RECURSIVE;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Specifies a custom dictionary provider for the annotated method or parameter. The specified
 * dictionary provider class must implement the {@link DictionaryProvider} interface.
 *
 * <p>The annotation can be applied to methods and parameters of any type. When applied to complex
 * types (e.g. custom classes), the annotation is expected to apply to all nested fields unless
 * specified otherwise via the {@link #constraint()} attribute.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * public class MyFuzzTarget {
 *
 *   public Stream<?> provide() {
 *     return Stream.of("example1", "example2", "example3", 1232187321, -182371);
 *   }
 *
 *   @DictionaryProvider("provide")
 *   @FuzzTest
 *   public void fuzzerTestOneInput(String input) {
 *     // Fuzzing logic here
 *   }
 * }
 * }</pre>
 */
@Target({ElementType.METHOD, TYPE_USE})
@Retention(RUNTIME)
@PropertyConstraint
public @interface DictionaryProvider {
  String[] value() default {""};

  /*
   * This {@code DictionaryProvider} will be used with probability {@code 1/p} by the mutator responsible for
   * fitting types. Not all mutators respect this probability.
   */
  int pInv() default 10;

  /**
   * Defines the scope of the annotation. Possible values are defined in {@link
   * com.code_intelligence.jazzer.mutation.utils.PropertyConstraint}. It is convenient to use {@code
   * RECURSIVE} as the default value here, as dictionary objects are typically used for complex
   * types (e.g. custom classes) where the annotation is placed directly on the method or parameter
   * and is expected to apply to all nested fields.
   */
  String constraint() default RECURSIVE;
}
