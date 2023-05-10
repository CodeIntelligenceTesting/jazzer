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

package com.code_intelligence.jazzer.mutation;

import static com.code_intelligence.jazzer.mutation.mutator.Mutators.validateAnnotationUsage;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithReadExactly;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.combinator.ProductMutator;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.InputStreamSupport.ReadExactlyInputStream;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Optional;

public final class ArgumentsMutator {
  private final Object instance;
  private final Method method;
  private final ProductMutator productMutator;
  private Object[] arguments;

  /**
   * True if the arguments array has already been passed to a user-provided function or exposed
   * via {@link #getArguments()} without going through {@link ProductMutator#detach(Object[])}.
   * In this case the arguments may have been modified externally, which interferes with mutation,
   * or could have been stored in static state that would be affected by future mutations.
   * Arguments should either be detached or not be reused after being exposed, which is enforced by
   * this variable.
   */
  private boolean argumentsExposed;

  private ArgumentsMutator(Object instance, Method method, ProductMutator productMutator) {
    this.instance = instance;
    this.method = method;
    this.productMutator = productMutator;
  }

  private static String prettyPrintMethod(Method method) {
    return format("%s.%s(%s)", method.getDeclaringClass().getName(), method.getName(),
        stream(method.getAnnotatedParameterTypes()).map(Object::toString).collect(joining(", ")));
  }

  public static ArgumentsMutator forInstanceMethodOrThrow(Object instance, Method method) {
    return forInstanceMethod(Mutators.newFactory(), instance, method)
        .orElseThrow(()
                         -> new IllegalArgumentException(
                             "Failed to construct mutator for " + prettyPrintMethod(method)));
  }

  public static ArgumentsMutator forStaticMethodOrThrow(Method method) {
    return forStaticMethod(Mutators.newFactory(), method)
        .orElseThrow(()
                         -> new IllegalArgumentException(
                             "Failed to construct mutator for " + prettyPrintMethod(method)));
  }

  public static Optional<ArgumentsMutator> forMethod(Method method) {
    return forMethod(Mutators.newFactory(), null, method);
  }

  public static Optional<ArgumentsMutator> forInstanceMethod(
      MutatorFactory mutatorFactory, Object instance, Method method) {
    require(!isStatic(method), "method must not be static");
    requireNonNull(instance, "instance must not be null");
    require(method.getDeclaringClass().isInstance(instance),
        format("instance is a %s, expected %s", instance.getClass(), method.getDeclaringClass()));
    return forMethod(mutatorFactory, instance, method);
  }

  public static Optional<ArgumentsMutator> forStaticMethod(
      MutatorFactory mutatorFactory, Method method) {
    require(isStatic(method), "method must be static");
    return forMethod(mutatorFactory, null, method);
  }

  public static Optional<ArgumentsMutator> forMethod(
      MutatorFactory mutatorFactory, Object instance, Method method) {
    require(method.getParameterCount() > 0, "Can't fuzz method without parameters: " + method);
    for (AnnotatedType parameter : method.getAnnotatedParameterTypes()) {
      validateAnnotationUsage(parameter);
    }
    return toArrayOrEmpty(
        stream(method.getAnnotatedParameterTypes()).map(mutatorFactory::tryCreate),
        SerializingMutator<?>[] ::new)
        .map(MutatorCombinators::mutateProduct)
        .map(productMutator -> ArgumentsMutator.create(instance, method, productMutator));
  }

  private static ArgumentsMutator create(
      Object instance, Method method, ProductMutator productMutator) {
    method.setAccessible(true);

    return new ArgumentsMutator(instance, method, productMutator);
  }

  private static boolean isStatic(Method method) {
    return Modifier.isStatic(method.getModifiers());
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
   * @return if the given input stream was consumed exactly
   * @throws UncheckedIOException if the underlying InputStream throws
   */
  public boolean read(ByteArrayInputStream data) {
    try {
      ReadExactlyInputStream is = extendWithReadExactly(data);
      arguments = productMutator.readExclusive(is);
      argumentsExposed = false;
      return is.isConsumedExactly();
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
    productMutator.mutate(arguments, prng);
  }

  public void invoke(boolean detach) throws Throwable {
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
    Preconditions.check(!argumentsExposed,
        "Arguments have previously been exposed to user-provided code without calling #detach and may have been modified");
  }
}
