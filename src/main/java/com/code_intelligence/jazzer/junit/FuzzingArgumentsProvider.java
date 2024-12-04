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
