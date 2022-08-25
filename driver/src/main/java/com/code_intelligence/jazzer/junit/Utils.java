// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.junit;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class Utils {
  static String defaultSeedCorpusPath(Class<?> testClass) {
    return testClass.getSimpleName() + "SeedCorpus";
  }

  static String defaultInstrumentationFilter(Class<?> testClass) {
    // This is an extremely rough "implementation" of the public suffix list algorithm
    // (https://publicsuffix.org/): It tries to guess the shortest prefix of the package name that
    // isn't public. It doesn't use the actual list, but instead assumes that every root segment as
    // well as "com.github" are public. Examples:
    // - com.example.Test --> com.example.**
    // - com.example.foobar.Test --> com.example.**
    // - com.github.someones.repo.Test --> com.github.someones.**
    String packageName = testClass.getPackage().getName();
    String[] packageSegments = packageName.split("\\.");
    int numSegments = 2;
    if (packageSegments.length > 2 && packageSegments[0].equals("com")
        && packageSegments[1].equals("github")) {
      numSegments = 3;
    }
    return Stream.concat(Arrays.stream(packageSegments).limit(numSegments), Stream.of("**"))
        .collect(Collectors.joining("."));
  }
}
