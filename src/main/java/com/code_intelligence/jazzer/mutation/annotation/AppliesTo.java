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

package com.code_intelligence.jazzer.mutation.annotation;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * A meta-annotation that limits the concrete types an annotation for type usages applies to.
 */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
public @interface AppliesTo {
  /**
   * The meta-annotated annotation can be applied to these classes.
   */
  Class<?>[] value() default {};

  /**
   * The meta-annotated annotation can be applied to subclasses of these classes.
   */
  Class<?>[] subClassesOf() default {};
}
