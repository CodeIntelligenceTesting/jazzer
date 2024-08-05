/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
