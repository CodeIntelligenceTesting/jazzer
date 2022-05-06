// Copyright 2021 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.utils

import java.lang.IllegalArgumentException

private val BASE_INCLUDED_CLASS_NAME_GLOBS = listOf(
    "**", // everything
)

private val BASE_EXCLUDED_CLASS_NAME_GLOBS = listOf(
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
)

class ClassNameGlobber(includes: List<String>, excludes: List<String>) {
    // If no include globs are provided, start with all classes.
    private val includeMatchers = includes.ifEmpty { BASE_INCLUDED_CLASS_NAME_GLOBS }
        .map(::SimpleGlobMatcher)

    // If no include globs are provided, additionally exclude stdlib classes as well as our own classes.
    private val excludeMatchers = (if (includes.isEmpty()) BASE_EXCLUDED_CLASS_NAME_GLOBS + excludes else excludes)
        .map(::SimpleGlobMatcher)

    fun includes(className: String): Boolean {
        return includeMatchers.any { it.matches(className) } && excludeMatchers.none { it.matches(className) }
    }
}

class SimpleGlobMatcher(val glob: String) {
    private enum class Type {
        // foo.bar (matches foo.bar only)
        FULL_MATCH,
        // foo.** (matches foo.bar and foo.bar.baz)
        PATH_WILDCARD_SUFFIX,
        // foo.* (matches foo.bar, but not foo.bar.baz)
        SEGMENT_WILDCARD_SUFFIX,
    }

    private val type: Type
    private val prefix: String

    init {
        // Remain compatible with globs such as "\\[" that use escaping.
        val pattern = glob.replace("\\", "")
        when {
            !pattern.contains('*') -> {
                type = Type.FULL_MATCH
                prefix = pattern
            }
            // Ends with "**" and contains no other '*'.
            pattern.endsWith("**") && pattern.indexOf('*') == pattern.length - 2 -> {
                type = Type.PATH_WILDCARD_SUFFIX
                prefix = pattern.removeSuffix("**")
            }
            // Ends with "*" and contains no other '*'.
            pattern.endsWith('*') && pattern.indexOf('*') == pattern.length - 1 -> {
                type = Type.SEGMENT_WILDCARD_SUFFIX
                prefix = pattern.removeSuffix("*")
            }
            else -> throw IllegalArgumentException(
                "Unsupported glob pattern (only foo.bar, foo.* and foo.** are supported): $pattern"
            )
        }
    }

    /**
     * Checks whether [maybeInternalClassName], which may be internal (foo/bar) or not (foo.bar), matches [glob].
     */
    fun matches(maybeInternalClassName: String): Boolean {
        val className = maybeInternalClassName.replace('/', '.')
        return when (type) {
            Type.FULL_MATCH -> className == prefix
            Type.PATH_WILDCARD_SUFFIX -> className.startsWith(prefix)
            Type.SEGMENT_WILDCARD_SUFFIX -> {
                // className starts with prefix and contains no further '.'.
                className.startsWith(prefix) &&
                    className.indexOf('.', startIndex = prefix.length) == -1
            }
        }
    }
}
