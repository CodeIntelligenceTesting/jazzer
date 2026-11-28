/*
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
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import com.code_intelligence.jazzer.mutation.utils.AppliesTo;
import com.code_intelligence.jazzer.mutation.utils.IgnoreRecursiveConflicts;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/** Excludes JavaBean setter methods whose name matches any entry in {@link #value()}. */
@Target({METHOD, TYPE_USE})
@Retention(RUNTIME)
@AppliesTo(subClassesOf = Object.class)
@IgnoreRecursiveConflicts
@PropertyConstraint
public @interface IgnoreSetters {
  /** Setter method names to ignore (e.g., {@code "setFoo"}, {@code "withBar"}). */
  String[] value();

  /**
   * Defines the scope of the annotation. Possible values are defined in {@link
   * com.code_intelligence.jazzer.mutation.utils.PropertyConstraint}. Defaults to {@code RECURSIVE}.
   */
  String constraint() default RECURSIVE;
}
