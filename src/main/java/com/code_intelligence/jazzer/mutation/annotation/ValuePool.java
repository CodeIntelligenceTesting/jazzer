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
 * Provides values to user-selected types that will be used during mutation.
 *
 * <p>This annotation can be applied to fuzz test methods and any parameter type or subtype. By
 * default, this annotation is propagated to all nested subtypes unless specified otherwise via the
 * {@link #constraint()} attribute.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * public class MyFuzzTargets {
 *
 *   static Stream<?> valuesVisibleByAllArgumentMutators() {
 *     return Stream.of("example1", "example2", "example3", 1232187321, -182371);
 *   }
 *
 *   static Stream<?> valuesVisibleOnlyByAnotherInput() {
 *     return Stream.of("code-intelligence.com", "secret.url.1082h3u21ibsdsazuvbsa.com");
 *   }
 *
 *   @ValuePool("valuesVisibleByAllArgumentMutators")
 *   @FuzzTest
 *   public void fuzzerTestOneInput(String input, @ValuePool("valuesVisibleOnlyByAnotherInput") String anotherInput) {
 *     // Fuzzing logic here
 *   }
 * }
 * }</pre>
 *
 * In this example, the mutator for the String parameter {@code input} of the fuzz test method
 * {@code fuzzerTestOneInput} will be using the values returned by {@code
 * valuesVisibleByAllArgumentMutators} method during mutation, while the mutator for String {@code
 * anotherInput} will use values from both methods: from the method-level {@code ValuePool}
 * annotation that uses {@code valuesVisibleByAllArgumentMutators} and the parameter-level {@code
 * ValuePool} annotation that uses {@code valuesVisibleOnlyByAnotherInput}.
 */
@Target({ElementType.METHOD, TYPE_USE})
@Retention(RUNTIME)
@IgnoreRecursiveConflicts
@PropertyConstraint
public @interface ValuePool {
  /**
   * Specifies supplier methods that generate values for fuzzing the annotated method or type. The
   * specified supplier methods must be static and return a {@code Stream<?>} of values. The values
   * don't need to match the type of the annotated method or parameter. The mutation framework will
   * extract only the values that are compatible with the target type.
   *
   * <p>Suppliers in the fuzz test class can be referenced by their method name, while suppliers in
   * other classes must be referenced by their fully qualified method name (e.g. {@code
   * com.example.MyClass#mySupplierMethod}), or for nested classes: {@code
   * com.example.OuterClass$InnerClass#mySupplierMethod}.
   */
  String[] value() default {};

  /**
   * Specifies glob patterns matching files that should be provided as {@code byte[]} to the
   * annotated type. The syntax follows closely to Java's {@link
   * java.nio.file.FileSystem#getPathMatcher(String) PathMatcher} "glob:" syntax.
   *
   * <p>Relative glob patterns are resolved against the working directory.
   *
   * <p><i>Note: Patterns that start with <code>{</code> or <code>[</code> are treated as relative
   * to the working directory.</i>
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>{@code *.jpeg} - matches all jpegs in the working directory
   *   <li>{@code **.xml} - matches all xml files recursively
   *   <li>{@code src/test/resources/dict/*.txt} - matches txt files in a specific directory
   *   <li>{@code /absolute/path/to/some/directory/**} - matches all files in an absolute path
   *       recursively
   *   <li><code>{"*.jpg", "**.png"}</code> - matches all jpg in the working directory, and png
   *       files recursively
   * </ul>
   */
  String[] files() default {};

  /**
   * This {@code ValuePool} will be used with probability {@code p} by the mutator responsible for
   * fitting types.
   */
  double p() default 0.1;

  /**
   * If the mutator selects a value from this {@code ValuePool}, it will perform up to {@code
   * maxMutations} additional mutations on the selected value.
   */
  int maxMutations() default 1;

  /**
   * Defines the scope of the annotation. Possible values are defined in {@link
   * com.code_intelligence.jazzer.mutation.utils.PropertyConstraint}. By default, it's {@code
   * RECURSIVE}.
   */
  String constraint() default RECURSIVE;
}
