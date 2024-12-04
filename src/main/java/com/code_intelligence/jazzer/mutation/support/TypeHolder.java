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

import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Type;

/**
 * A factory for {@link AnnotatedType} instances capturing types.
 *
 * <p>Due to type erasure, this class can only be used by creating an anonymous subclass.
 *
 * <p>Example: {@code new TypeHolder<List<String>> {}.annotatedType}
 *
 * <p>For primitive types {@link
 * com.code_intelligence.jazzer.mutation.support.TestSupport.ParameterHolder} has to be used
 * instead.
 *
 * @param <T> the type to hold
 */
public abstract class TypeHolder<T> {
  protected TypeHolder() {}

  public AnnotatedType annotatedType() {
    return ((AnnotatedParameterizedType) this.getClass().getAnnotatedSuperclass())
        .getAnnotatedActualTypeArguments()[0];
  }

  public Type type() {
    return annotatedType().getType();
  }
}
