/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import static com.code_intelligence.jazzer.junit.Utils.isFuzzing;

import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

class FuzzingArgumentsProvider implements ArgumentsProvider {
  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) {
    if (!isFuzzing(extensionContext)) {
      return Stream.empty();
    }

    // When fuzzing, supply a special set of arguments that our InvocationInterceptor uses as a
    // sign to start fuzzing.
    // FIXME: This is a hack that is needed only because there does not seem to be a way to
    //  communicate out of band that a certain invocation was triggered by a particular argument
    //  provider. We should get rid of this hack as soon as
    //  https://github.com/junit-team/junit5/issues/3282 has been addressed.
    return Stream.of(
        Utils.getMarkedArguments(extensionContext.getRequiredTestMethod(), "Fuzzing..."));
  }
}
