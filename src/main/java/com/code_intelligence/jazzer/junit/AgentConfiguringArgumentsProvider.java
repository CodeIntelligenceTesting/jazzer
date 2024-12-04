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
