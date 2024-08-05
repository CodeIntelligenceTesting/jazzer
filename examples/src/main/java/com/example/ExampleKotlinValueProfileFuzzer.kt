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

object ExampleKotlinValueProfileFuzzer {

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        if (data.consumeInt().compareTo(0x11223344) != 0) {
            return
        }
        if (encrypt(data.consumeLong()).compareTo(5788627691251634856) == 0 &&
            encrypt(data.consumeLong()).compareTo(6293579535917519017) == 0
        ) {
            throw FuzzerSecurityIssueMedium("Jazzer can handle integral comparisons in Kotlin")
        }
    }

    private fun encrypt(n: Long): Long {
        return n.xor(0x1122334455667788)
    }
}
