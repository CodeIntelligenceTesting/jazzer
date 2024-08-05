/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

import com.google.errorprone.annotations.DoNotMock;

/**
 * Combines a {@link ValueMutator} with a {@link Serializer} for objects of type {@code T}.
 *
 * <p>Implementing classes SHOULD be declared final.
 *
 * <p>This is the default fully-featured mutator type. If {@code T} can be mutated fully in place,
 * consider implementing the more versatile {@link SerializingInPlaceMutator} instead.
 */
@DoNotMock("Use TestSupport#mockMutator instead")
public abstract class SerializingMutator<T> implements Serializer<T>, ValueMutator<T> {
  @Override
  public final String toString() {
    return Debuggable.getDebugString(this);
  }
}
