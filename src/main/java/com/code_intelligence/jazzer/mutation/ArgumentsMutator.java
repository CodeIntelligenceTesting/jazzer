/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation;

import static com.code_intelligence.jazzer.mutation.mutator.Mutators.validateAnnotationUsage;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.combinator.ProductMutator;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Optional;

public final class ArgumentsMutator {
  private final Method method;
  private final ProductMutator productMutator;
  private Object[] arguments;

  /**
   * True if the arguments array has already been passed to a user-provided function or exposed via
   * {@link #getArguments()} without going through {@link ProductMutator#detach(Object[])}. In this
   * case the arguments may have been modified externally, which interferes with mutation, or could
   * have been stored in static state that would be affected by future mutations. Arguments should
   * either be detached or not be reused after being exposed, which is enforced by this variable.
   */
  private boolean argumentsExposed;

  private ArgumentsMutator(Method method, ProductMutator productMutator) {
    this.method = method;
    this.productMutator = productMutator;
  }

  private static String prettyPrintMethod(Method method) {
    return format(
        "%s.%s(%s)",
        method.getDeclaringClass().getName(),
        method.getName(),
        stream(method.getAnnotatedParameterTypes()).map(Object::toString).collect(joining(", ")));
  }

  public static ArgumentsMutator forMethodOrThrow(Method method) {
    return forMethod(Mutators.newFactory(), method)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Failed to construct mutator for " + prettyPrintMethod(method)));
  }

  public static Optional<ArgumentsMutator> forMethod(Method method) {
    return forMethod(Mutators.newFactory(), method);
  }

  public static Optional<ArgumentsMutator> forMethod(
      ExtendedMutatorFactory mutatorFactory, Method method) {
    require(method.getParameterCount() > 0, "Can't fuzz method without parameters: " + method);
    for (AnnotatedType parameter : method.getAnnotatedParameterTypes()) {
      validateAnnotationUsage(parameter);
    }
    return toArrayOrEmpty(
            stream(method.getAnnotatedParameterTypes()).map(mutatorFactory::tryCreate),
            SerializingMutator<?>[]::new)
        .map(MutatorCombinators::mutateProduct)
        .map(productMutator -> ArgumentsMutator.create(method, productMutator));
  }

  private static ArgumentsMutator create(Method method, ProductMutator productMutator) {
    method.setAccessible(true);

    return new ArgumentsMutator(method, productMutator);
  }

  /**
   * @throws UncheckedIOException if the underlying InputStream throws
   */
  public void crossOver(InputStream data1, InputStream data2, long seed) {
    try {
      Object[] objects1 = productMutator.readExclusive(data1);
      Object[] objects2 = productMutator.readExclusive(data2);
      PseudoRandom prng = new SeededPseudoRandom(seed);
      arguments = productMutator.crossOver(objects1, objects2, prng);
      argumentsExposed = false;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * @throws UncheckedIOException if the underlying InputStream throws
   */
  public void read(ByteArrayInputStream data) {
    try {
      arguments = productMutator.readExclusive(data);
      argumentsExposed = false;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * @throws UncheckedIOException if the underlying OutputStream throws
   */
  public void write(OutputStream data) {
    failIfArgumentsExposed();
    writeAny(data, arguments);
  }

  /**
   * @throws UncheckedIOException if the underlying OutputStream throws
   */
  public void writeAny(OutputStream data, Object[] args) throws UncheckedIOException {
    try {
      productMutator.writeExclusive(args, data);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  public void init(long seed) {
    init(new SeededPseudoRandom(seed));
  }

  void init(PseudoRandom prng) {
    arguments = productMutator.init(prng);
    argumentsExposed = false;
  }

  public void mutate(long seed) {
    mutate(new SeededPseudoRandom(seed));
  }

  void mutate(PseudoRandom prng) {
    failIfArgumentsExposed();
    // TODO: Sometimes mutate the entire byte representation of the current value with libFuzzer's
    //  dictionary and TORC mutations.
    productMutator.mutateInPlace(arguments, prng);
  }

  public void invoke(Object instance, boolean detach) throws Throwable {
    Object[] invokeArguments;
    if (detach) {
      invokeArguments = productMutator.detach(arguments);
    } else {
      invokeArguments = arguments;
      argumentsExposed = true;
    }
    try {
      method.invoke(instance, invokeArguments);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException("method should have been made accessible", e);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    }
  }

  public Object[] getArguments() {
    argumentsExposed = true;
    return arguments;
  }

  @Override
  public String toString() {
    return "Arguments" + productMutator;
  }

  private void failIfArgumentsExposed() {
    Preconditions.check(
        !argumentsExposed,
        "Arguments have previously been exposed to user-provided code without calling #detach and"
            + " may have been modified");
  }
}
