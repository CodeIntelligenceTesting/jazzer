/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example

class KotlinVararg(vararg opts: String) {
    private val allOpts = opts.toList().joinToString(", ")

    fun doStuff() = allOpts
}
