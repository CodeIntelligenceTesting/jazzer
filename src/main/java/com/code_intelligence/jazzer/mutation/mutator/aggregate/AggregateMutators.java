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

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.lang.reflect.InvocationTargetException;
import java.util.stream.Stream;

public final class AggregateMutators {
  private AggregateMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    // Register the record mutator first as it is more specific.
    return Stream.concat(
        newRecordMutatorFactoryIfSupported(),
        Stream.of(
            new SetterBasedBeanMutatorFactory(),
            new ConstructorBasedBeanMutatorFactory(),
            new CachedConstructorMutatorFactory()));
  }

  private static Stream<MutatorFactory> newRecordMutatorFactoryIfSupported() {
    if (!supportsRecords()) {
      return Stream.empty();
    }
    try {
      // Instantiate RecordMutatorFactory via reflection as making it a compile time dependency
      // breaks the r8 step in the Android build.
      Class<? extends MutatorFactory> recordMutatorFactory;
      recordMutatorFactory =
          Class.forName(AggregateMutators.class.getPackage().getName() + ".RecordMutatorFactory")
              .asSubclass(MutatorFactory.class);
      return Stream.of(recordMutatorFactory.getDeclaredConstructor().newInstance());
    } catch (ClassNotFoundException
        | NoSuchMethodException
        | InstantiationException
        | IllegalAccessException
        | InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean supportsRecords() {
    try {
      Class.forName("java.lang.Record");
      return true;
    } catch (ClassNotFoundException ignored) {
      return false;
    }
  }
}
