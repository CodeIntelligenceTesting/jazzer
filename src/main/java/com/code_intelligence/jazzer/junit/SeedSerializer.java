/*
 * Copyright 2024 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.junit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.mutation.ArgumentsMutator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;

interface SeedSerializer {
  Object[] read(byte[] bytes);

  // Implementations can assume that the argument array contains valid arguments for the method that
  // this instance has been constructed for.
  byte[] write(Object[] args) throws UnsupportedOperationException;

  /**
   * Creates specialized {@link SeedSerializer} instances for the following method parameters:
   *
   * <ul>
   *   <li>{@code byte[]}
   *   <li>{@code FuzzDataProvider}
   *   <li>Any other types will attempt to be created using the mutator framework
   * </ul>
   */
  static SeedSerializer of(Method method) {
    if (method.getParameterCount() == 0) {
      throw new FuzzTestConfigurationError(
          "Methods annotated with @FuzzTest must take at least one parameter");
    }
    if (method.getParameterCount() == 1 && method.getParameterTypes()[0] == byte[].class) {
      return new ByteArraySeedSerializer();
    } else if (method.getParameterCount() == 1
        && method.getParameterTypes()[0] == FuzzedDataProvider.class) {
      return new FuzzedDataProviderSeedSerializer();
    } else {
      try {
        return new ArgumentsMutatorSeedSerializer(ArgumentsMutator.forMethodOrThrow(method));
      } catch (IllegalArgumentException e) {
        // Wrap exception message from ArgumentsMutator in JUnit specific exception type.
        throw new FuzzTestConfigurationError(e.getMessage());
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

    public ArgumentsMutatorSeedSerializer(ArgumentsMutator mutator) {
      this.mutator = mutator;
    }

    @Override
    public Object[] read(byte[] bytes) {
      mutator.read(new ByteArrayInputStream(bytes));
      return mutator.getArguments();
    }

    @Override
    public byte[] write(Object[] args) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      mutator.writeAny(out, args);
      return out.toByteArray();
    }
  }
}
