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

package com.code_intelligence.jazzer.mutation.api;

import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;

import com.google.errorprone.annotations.CheckReturnValue;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import java.util.Optional;

/**
 * A {@link MutatorFactory} that delegates to the given factories in order.
 */
public final class ChainedMutatorFactory extends MutatorFactory {
  private final List<MutatorFactory> factories;

  /**
   * Creates a {@link MutatorFactory} that delegates to the given factories in order.
   *
   * @param factories a possibly empty collection of factories
   */
  public ChainedMutatorFactory(MutatorFactory... factories) {
    this.factories = unmodifiableList(asList(factories));
  }

  @Override
  @CheckReturnValue
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory parent) {
    return findFirstPresent(factories.stream().map(factory -> factory.tryCreate(type, parent)));
  }
}
