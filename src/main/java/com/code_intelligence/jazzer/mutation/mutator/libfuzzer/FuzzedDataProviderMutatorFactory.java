/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.libfuzzer;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class FuzzedDataProviderMutatorFactory implements MutatorFactory {
  @Override
  @SuppressWarnings("unchecked")
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, FuzzedDataProvider.class)
        .flatMap(parent -> factory.tryCreate(notNull(asAnnotatedType(byte[].class))))
        .map(
            byteArrayMutator ->
                mutateThenMap(
                    (SerializingMutator<byte[]>) byteArrayMutator,
                    FuzzedDataProviderImpl::withJavaData,
                    FuzzedDataProviderImpl::getJavaData,
                    (Predicate<Debuggable> inCycle) -> "FuzzedDataProvider"));
  }
}
