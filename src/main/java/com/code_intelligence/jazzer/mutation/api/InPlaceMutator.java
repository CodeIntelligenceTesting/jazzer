/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

/**
 * Knows how to initialize and mutate (parts of) an existing object of type {@code T} in place and
 * how to incorporate (cross over) parts of another object of the same type.
 *
 * <p>Certain types, such as immutable and primitive types, can not be mutated in place. For
 * example, {@link java.util.List} can be mutated in place whereas {@link String} and {@code int}
 * can't. In such cases, use {@link ValueMutator} instead.
 *
 * <p>Implementations
 *
 * <ul>
 *   <li>MAY weakly associate mutable state with the identity (not equality class) of objects they
 *       have been passed as arguments or returned from initialization functions;
 *   <li>MAY assume that they are only passed arguments that they have initialized or mutated;
 *   <li>SHOULD use {@link com.code_intelligence.jazzer.mutation.support.WeakIdentityHashMap} for
 *       this purpose;
 *   <li>MUST otherwise be deeply immutable;
 *   <li>SHOULD override {@link Object#toString()} to return {@code
 *       Debuggable.getDebugString(this)}.
 * </ul>
 *
 * @param <T> the reference type this mutator operates on
 */
public interface InPlaceMutator<T> extends Debuggable, MutatorBase {
  /**
   * Implementations
   *
   * <ul>
   *   <li>MUST accept any mutable instance of {@code T}, not just those it creates itself.
   *   <li>SHOULD, when called repeatedly, initialize the object in ways that are likely to be
   *       distinct.
   * </ul>
   */
  void initInPlace(T reference, PseudoRandom prng);

  /**
   * Implementations
   *
   * <ul>
   *   <li>MUST ensure that {@code reference} does not {@link Object#equals(Object)} the state it
   *       had prior to the call (if possible);
   *   <li>MUST accept any mutable instance of {@code T}, not just those it creates itself.
   *   <li>SHOULD, when called repeatedly, be able to eventually reach any valid state of the part
   *       of {@code T} governed by this mutator;
   * </ul>
   */
  void mutateInPlace(T reference, PseudoRandom prng);

  /**
   * Implementations
   *
   * <ul>
   *   <li>MUST ensure that {@code reference} does not {@link Object#equals(Object)} the state it
   *       had prior to the call (if possible);
   *   <li>MUST accept any mutable instance of {@code T}, not just those it creates itself.
   *   <li>MUST NOT mutate {@code otherReference}
   * </ul>
   */
  void crossOverInPlace(T reference, T otherReference, PseudoRandom prng);
}
