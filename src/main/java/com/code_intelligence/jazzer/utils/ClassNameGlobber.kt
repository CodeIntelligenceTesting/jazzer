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

package com.code_intelligence.jazzer.utils

private val BASE_INCLUDED_CLASS_NAME_GLOBS =
    listOf(
        "**", // everything
    )

// We use both a strong indicator for running as a Bazel test together with an indicator for a
// Bazel coverage run to rule out false positives.
private val IS_BAZEL_COVERAGE_RUN =
    System.getenv("TEST_UNDECLARED_OUTPUTS_DIR") != null &&
        System.getenv("COVERAGE_DIR") != null

private val ADDITIONAL_EXCLUDED_NAME_GLOBS_FOR_BAZEL_COVERAGE =
    listOf(
        "com.google.testing.coverage.**",
        "org.jacoco.**",
    )

private val BASE_EXCLUDED_CLASS_NAME_GLOBS =
    listOf(
        // JDK internals
        "\\[**", // array types
        "java.**",
        "javax.**",
        "jdk.**",
        "sun.**",
        "com.sun.**", // package for Proxy objects
        // Azul JDK internals
        "com.azul.tooling.**",
        // Kotlin internals
        "kotlin.**",
        // Jazzer internals
        "com.code_intelligence.jazzer.**",
        "jaz.Ter", // safe companion of the honeypot class used by sanitizers
        "jaz.Zer", // honeypot class used by sanitizers
        // Test and instrumentation tools
        "org.junit.**", // dependency of @FuzzTest
        "org.mockito.**", // can cause instrumentation cycles
        "net.bytebuddy.**", // ignore Byte Buddy, though it's probably shaded
        "org.jetbrains.**", // ignore JetBrains products (coverage agent)
    ) + if (IS_BAZEL_COVERAGE_RUN) ADDITIONAL_EXCLUDED_NAME_GLOBS_FOR_BAZEL_COVERAGE else listOf()

class ClassNameGlobber(
    includes: List<String>,
    excludes: List<String>,
) {
    // If no include globs are provided, start with all classes.
    private val includeMatchers =
        includes
            .ifEmpty { BASE_INCLUDED_CLASS_NAME_GLOBS }
            .map(::SimpleGlobMatcher)

    // If no include globs are provided, additionally exclude stdlib classes as well as our own classes.
    private val excludeMatchers =
        (if (includes.isEmpty()) BASE_EXCLUDED_CLASS_NAME_GLOBS + excludes else excludes)
            .map(::SimpleGlobMatcher)

    fun includes(className: String): Boolean =
        includeMatchers.any { it.matches(className) } && excludeMatchers.none { it.matches(className) }
}
