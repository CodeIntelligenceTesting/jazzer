/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

import java.util.function.Function;

@FunctionalInterface
public interface Function1<T1, R> extends Function<T1, R> {
  @Override
  R apply(T1 t1);
}
