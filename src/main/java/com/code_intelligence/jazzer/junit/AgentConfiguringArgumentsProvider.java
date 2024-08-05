/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

class AgentConfiguringArgumentsProvider implements ArgumentsProvider, AnnotationConsumer<FuzzTest> {
  private FuzzTest fuzzTest;

  @Override
  public void accept(FuzzTest fuzzTest) {
    this.fuzzTest = fuzzTest;
  }

  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext)
      throws Exception {
    // FIXME(fmeum): Calling this here feels like a hack. There should be a lifecycle hook that runs
    //  before the argument discovery for a ParameterizedTest is kicked off, but I haven't found
    //  one.
    Optional<Path> dictionaryPath =
        FuzzerDictionary.createDictionaryFile(extensionContext.getRequiredTestMethod());
    // We need to call this method here in addition to the call in FuzzTestExtensions as our
    // ArgumentProviders need the bootstrap jar on the classpath and there may be no user-provided
    // ArgumentProviders to trigger the call in FuzzTestExtensions.
    FuzzTestExecutor.configureAndInstallAgent(
        extensionContext, fuzzTest.maxDuration(), fuzzTest.maxExecutions(), dictionaryPath);
    return Stream.empty();
  }
}
