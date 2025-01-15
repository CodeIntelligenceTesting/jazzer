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
    return Stream.of(
            newRecordMutatorFactoryIfSupported(),
            newSealedClassMutatorFactoryIfSupported(),
            Stream.of(
                new SetterBasedBeanMutatorFactory(),
                new ConstructorBasedBeanMutatorFactory(),
                new CachedConstructorMutatorFactory()))
        .flatMap(s -> s);
  }

  private static Stream<MutatorFactory> newRecordMutatorFactoryIfSupported() {
    try {
      Class.forName("java.lang.Record");
      return Stream.of(instantiateMutatorFactory("RecordMutatorFactory"));
    } catch (ClassNotFoundException ignored) {
      return Stream.empty();
    }
  }

  private static Stream<MutatorFactory> newSealedClassMutatorFactoryIfSupported() {
    try {
      Class.class.getMethod("getPermittedSubclasses");
      return Stream.of(instantiateMutatorFactory("SealedClassMutatorFactory"));
    } catch (NoSuchMethodException e) {
      return Stream.empty();
    }
  }

  private static MutatorFactory instantiateMutatorFactory(String simpleClassName) {
    try {
      // Instantiate factory via reflection as making it a compile time dependency breaks the r8
      // step in the Android build.
      Class<? extends MutatorFactory> factory;
      factory =
          Class.forName(AggregateMutators.class.getPackage().getName() + "." + simpleClassName)
              .asSubclass(MutatorFactory.class);
      return factory.getDeclaredConstructor().newInstance();
    } catch (ClassNotFoundException
        | NoSuchMethodException
        | InstantiationException
        | IllegalAccessException
        | InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
  }
}
