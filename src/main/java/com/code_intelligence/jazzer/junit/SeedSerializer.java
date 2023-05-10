/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.junit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.Meta;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.mutation.ArgumentsMutator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.Optional;

interface SeedSerializer {
  Object[] read(byte[] bytes);
  default boolean allReadsValid() {
    return true;
  }

  // Implementations can assume that the argument array contains valid arguments for the method that
  // this instance has been constructed for.
  byte[] write(Object[] args) throws UnsupportedOperationException;

  /**
   * Creates specialized {@link SeedSerializer} instances for the following method parameters:
   * <ul>
   *   <li>{@code byte[]}
   *   <li>{@code FuzzDataProvider}
   *   <li>Any other types will attempt to be created using either Autofuzz or the experimental
   * mutator framework if {@link Opt}'s {@code experimentalMutator} is set.
   * </ul>
   */
  static SeedSerializer of(Method method) {
    if (method.getParameterCount() == 0) {
      throw new IllegalArgumentException(
          "Methods annotated with @FuzzTest must take at least one parameter");
    }
    if (method.getParameterCount() == 1 && method.getParameterTypes()[0] == byte[].class) {
      return new ByteArraySeedSerializer();
    } else if (method.getParameterCount() == 1
        && method.getParameterTypes()[0] == FuzzedDataProvider.class) {
      return new FuzzedDataProviderSeedSerializer();
    } else {
      Optional<ArgumentsMutator> argumentsMutator =
          Opt.experimentalMutator ? ArgumentsMutator.forMethod(method) : Optional.empty();
      return argumentsMutator.<SeedSerializer>map(ArgumentsMutatorSeedSerializer::new)
          .orElseGet(() -> new AutofuzzSeedSerializer(method));
    }
  }
}

final class ByteArraySeedSerializer implements SeedSerializer {
  @Override
  public Object[] read(byte[] bytes) {
    return new Object[] {bytes};
  }

  @Override
  public byte[] write(Object[] args) {
    return (byte[]) args[0];
  }
}

final class FuzzedDataProviderSeedSerializer implements SeedSerializer {
  @Override
  public Object[] read(byte[] bytes) {
    return new Object[] {FuzzedDataProviderImpl.withJavaData(bytes)};
  }

  @Override
  public byte[] write(Object[] args) throws UnsupportedOperationException {
    // While we could get the underlying bytes, it's not possible to provide Java seeds for fuzz
    // tests with a FuzzedDataProvider parameter.
    throw new UnsupportedOperationException();
  }
}

final class ArgumentsMutatorSeedSerializer implements SeedSerializer {
  private final ArgumentsMutator mutator;
  private boolean allReadsValid;

  public ArgumentsMutatorSeedSerializer(ArgumentsMutator mutator) {
    this.mutator = mutator;
  }

  @Override
  public Object[] read(byte[] bytes) {
    allReadsValid &= mutator.read(new ByteArrayInputStream(bytes));
    return mutator.getArguments();
  }

  @Override
  public boolean allReadsValid() {
    return allReadsValid;
  }

  @Override
  public byte[] write(Object[] args) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    mutator.writeAny(out, args);
    return out.toByteArray();
  }
}

final class AutofuzzSeedSerializer implements SeedSerializer {
  private final Meta meta;
  private final Method method;

  public AutofuzzSeedSerializer(Method method) {
    this.meta = new Meta(method.getDeclaringClass());
    this.method = method;
  }

  @Override
  public Object[] read(byte[] bytes) {
    try (FuzzedDataProviderImpl data = FuzzedDataProviderImpl.withJavaData(bytes)) {
      // The Autofuzz FuzzTarget uses data to construct an instance of the test class before
      // it constructs the fuzz test arguments. We don't need the instance here, but still
      // generate it as that mutates the FuzzedDataProvider state.
      meta.consumeNonStatic(data, method.getDeclaringClass());
      return meta.consumeArguments(data, method, null);
    }
  }

  @Override
  public byte[] write(Object[] args) throws UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }
}
