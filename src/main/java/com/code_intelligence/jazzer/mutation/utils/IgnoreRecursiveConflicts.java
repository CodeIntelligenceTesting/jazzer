/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.utils;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * A meta-annotation to turn off the check in {@code checkExtraAnnotations} that throws if some
 * annotation is present multiple times on a type. This allows annotations to be propagated down the
 * type hierarchy and accumulated along the way.
 *
 * <p>E.g. {@code @A("data1") List<@A("data2") String> arg} - the String mutator can see of
 * {@code @A("data1")} and {@code @A("data2")}, but the List mutator can only see
 * {@code @A("data1")}.
 */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
@Documented
public @interface IgnoreRecursiveConflicts {}
