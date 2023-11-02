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
import com.google.errorprone.annotations.ForOverride;

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
  private Boolean cachedHasFixedSize;

  @Override
  public final String toString() {
    return Debuggable.getDebugString(this);
  }

  @Override
  public boolean hasFixedSize() {
    if (cachedHasFixedSize != null) {
      return cachedHasFixedSize;
    }
    // If the type to mutate is recursive, computeHasFixedSize() may call back into hasFixedSize().
    // Ensure that the innermost call returns false to terminate the cycle and rely on all
    // intermediate calls to propagate false up to the outermost call. This is safe since only the
    // outermost call will ever reach this code (mutators are explicitly not thread-safe).
    cachedHasFixedSize = false;
    cachedHasFixedSize = computeHasFixedSize();
    return cachedHasFixedSize;
  }

  /**
   * Computes the value of {@link ValueMutator#hasFixedSize()} by inspecting the return value of
   * that function for child mutators.
   *
   * <p>If the return value is a constant, override {@link ValueMutator#hasFixedSize()} directly.
   */
  @ForOverride
  protected boolean computeHasFixedSize() {
    throw new UnsupportedOperationException(
        "Subclasses of SerializingMutator must override hasFixedSize or computeHasFixedSize");
  }
}
