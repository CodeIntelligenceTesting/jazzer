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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.util.stream.Collectors.toList;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;

/**
 * A factory for {@link AnnotatedType} instances capturing method parameters.
 *
 * <p>Due to type erasure, this class can only be used by creating an anonymous subclass with a
 * method called {@code foo} that takes exactly the desired parameter.
 *
 * <p>Example: {@code new ParameterHolder {void foo(@NotNull List<String> param)}.annotatedType}
 */
public abstract class ParameterHolder {
  protected ParameterHolder() {}

  public AnnotatedType annotatedType() {
    return getMethod().getAnnotatedParameterTypes()[0];
  }

  public Type type() {
    return annotatedType().getType();
  }

  public Annotation[] parameterAnnotations() {
    return getMethod().getParameterAnnotations()[0];
  }

  private Method getMethod() {
    List<Method> foos = Arrays.stream(this.getClass().getDeclaredMethods())
                            .filter(method -> method.getName().equals("foo"))
                            .collect(toList());
    require(foos.size() == 1,
        this.getClass().getName() + " must define exactly one function named 'foo'");
    Method foo = foos.get(0);
    require(foo.getParameterCount() == 1,
        this.getClass().getName() + "#foo must define exactly one parameter");
    return foo;
  }
}
