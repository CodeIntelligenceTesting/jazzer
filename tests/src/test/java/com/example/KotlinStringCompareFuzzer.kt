/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example

import java.io.IOException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object KotlinStringCompareFuzzer {
    @JvmStatic
    @OptIn(ExperimentalEncodingApi::class)
    fun fuzzerTestOneInput(data: ByteArray) {
        val text = Base64.encode(data)
        if (text.startsWith("aGVsbG8K") && // hello
            text.endsWith("d29ybGQK") // world
        ) {
            throw IOException("Found the secret message!")
        }
    }
}
