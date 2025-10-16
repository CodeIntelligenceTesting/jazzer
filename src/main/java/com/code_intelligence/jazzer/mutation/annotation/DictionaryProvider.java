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

import com.code_intelligence.jazzer.mutation.utils.IgnoreRecursiveConflicts;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Provides dictionary values to user-selected mutator types. Currently supported mutators are:
 *
 * <ul>
 *   <li>String mutator
 *   <li>Integral mutators (byte, short, int, long)
 * </ul>
 *
 * <p>This annotation can be applied to fuzz test methods and any parameter type or subtype. By
 * default, this annotation is propagated to all nested subtypes unless specified otherwise via the
 * {@link #constraint()} attribute.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * public class MyFuzzTarget {
 *
 *   static Stream<?> dictionaryVisibleByAllArgumentMutators() {
 *     return Stream.of("example1", "example2", "example3", 1232187321, -182371);
 *   }
 *
 *   static Stream<?> dictionaryVisibleOnlyByAnotherInput() {
 *     return Stream.of("code-intelligence.com", "secret.url.1082h3u21ibsdsazuvbsa.com");
 *   }
 *
 *   @DictionaryProvider("dictionaryVisibleByAllArgumentMutators")
 *   @FuzzTest
 *   public void fuzzerTestOneInput(String input, @DictionaryProvider("dictionaryVisibleOnlyByAnotherInput") String anotherInput) {
 *     // Fuzzing logic here
 *   }
 * }
 * }</pre>
 *
 * In this example, the mutator for the String parameter {@code input} of the fuzz test method
 * {@code fuzzerTestOneInput} will be using the values returned by {@code provide} method during
 * mutation, while the mutator for String {@code anotherInput} will use values from both methods:
 * from the method-level {@code DictionaryProvider} annotation that uses {@code provide} and the
 * parameter-level {@code DictionaryProvider} annotation that uses {@code provideSomethingElse}.
 */
@Target({ElementType.METHOD, TYPE_USE})
@Retention(RUNTIME)
@IgnoreRecursiveConflicts
@PropertyConstraint
public @interface DictionaryProvider {
  /**
   * Specifies supplier methods that generate dictionary values for fuzzing the annotated method or
   * type. The specified supplier methods must be static and return a {@code Stream <?>} of values.
   * The values don't need to match the type of the annotated method or parameter exactly. The
   * mutation framework will extract only the values that are compatible with the target type.
   */
  String[] value() default {""};

  /**
   * This {@code DictionaryProvider} will be used with probability {@code 1/p} by the mutator
   * responsible for fitting types. Not all mutators respect this probability.
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
