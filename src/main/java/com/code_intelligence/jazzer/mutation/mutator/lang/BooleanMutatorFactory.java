/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.errorprone.annotations.Immutable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class BooleanMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return findFirstParentIfClass(type, boolean.class, Boolean.class)
        .map(parent -> BooleanMutator.INSTANCE);
  }

  @Immutable
  private static final class BooleanMutator extends SerializingMutator<Boolean> {
    private static final BooleanMutator INSTANCE = new BooleanMutator();

    @Override
    public Boolean read(DataInputStream in) throws IOException {
      return in.readBoolean();
    }

    @Override
    public void write(Boolean value, DataOutputStream out) throws IOException {
      out.writeBoolean(value);
    }

    @Override
    public Boolean init(PseudoRandom prng) {
      return prng.choice();
    }

    @Override
    public Boolean mutate(Boolean value, PseudoRandom prng) {
      return !value;
    }

    @Override
    public Boolean crossOver(Boolean value, Boolean otherValue, PseudoRandom prng) {
      return prng.choice() ? value : otherValue;
    }

    @Override
    public boolean hasFixedSize() {
      return true;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInLoop) {
      return "Boolean";
    }

    @Override
    public Boolean detach(Boolean value) {
      return value;
    }
  }
}
