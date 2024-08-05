/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
    List<Method> foos =
        Arrays.stream(this.getClass().getDeclaredMethods())
            .filter(method -> method.getName().equals("foo"))
            .collect(toList());
    require(
        foos.size() == 1,
        this.getClass().getName() + " must define exactly one function named 'foo'");
    Method foo = foos.get(0);
    require(
        foo.getParameterCount() == 1,
        this.getClass().getName() + "#foo must define exactly one parameter");
    return foo;
  }
}
