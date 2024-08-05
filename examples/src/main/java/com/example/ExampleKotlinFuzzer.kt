/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium

object ExampleKotlinFuzzer {

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        exploreMe(data.consumeString(8), data.consumeInt(), data.consumeRemainingAsString())
    }

    private fun exploreMe(prefix: String, n: Int, suffix: String) {
        if (prefix.findAnyOf(arrayListOf("Fuzz", "Test")) != null) {
            if (n >= 2000000) {
                if (suffix.startsWith("@")) {
                    if (suffix.substring(1) == "Jazzer") {
                        throw FuzzerSecurityIssueMedium("Jazzer resolved string comparisons in Kotlin")
                    }
                }
            }
        }
    }
}
