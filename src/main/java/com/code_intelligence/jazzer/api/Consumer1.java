/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

import java.util.function.Consumer;

@FunctionalInterface
public interface Consumer1<T1> extends Consumer<T1> {
  @Override
  void accept(T1 t1);
}
