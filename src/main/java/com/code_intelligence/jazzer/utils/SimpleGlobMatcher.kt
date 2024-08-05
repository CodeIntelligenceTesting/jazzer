/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils

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
                "Unsupported glob pattern (only foo.bar, foo.* and foo.** are supported): $pattern",
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
