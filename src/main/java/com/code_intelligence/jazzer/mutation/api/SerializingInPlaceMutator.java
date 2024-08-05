/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

import static com.code_intelligence.jazzer.mutation.support.ExceptionSupport.asUnchecked;

import com.google.errorprone.annotations.ForOverride;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Combines an {@link InPlaceMutator} with a {@link Serializer} for objects of type {@code T}.
 *
 * <p>If {@code T} can't be mutated in place, implement {@link SerializingMutator} instead.
 *
 * <p>Implementing classes SHOULD be declared final.
 */
public abstract class SerializingInPlaceMutator<T> extends SerializingMutator<T>
    implements InPlaceMutator<T> {
  // ByteArrayInputStream#close is documented as being a no-op, so it is safe to reuse an instance
  // here.
  // TODO: Introduce a dedicated empty InputStream implementation.
  private static final InputStream emptyInputStream = new ByteArrayInputStream(new byte[0]);

  /**
   * Constructs a default instance of {@code T}.
   *
   * <p>The returned value is immediately passed to {@link #initInPlace(Object, PseudoRandom)}.
   *
   * <p>Implementing classes SHOULD provide a more efficient implementation.
   *
   * @return a default instance of {@code T}
   */
  @ForOverride
  protected T makeDefaultInstance() {
    try {
      return readExclusive(emptyInputStream);
    } catch (IOException e) {
      throw asUnchecked(e);
    }
  }

  @Override
  public final T init(PseudoRandom prng) {
    T value = makeDefaultInstance();
    initInPlace(value, prng);
    return value;
  }

  @Override
  public final T mutate(T value, PseudoRandom prng) {
    mutateInPlace(value, prng);
    return value;
  }

  @Override
  public final T crossOver(T value, T otherValue, PseudoRandom prng) {
    crossOverInPlace(value, otherValue, prng);
    return value;
  }
}
