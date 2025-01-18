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

package com.example

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium

object ExampleKotlinFuzzer {
    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        exploreMe(data.consumeString(8), data.consumeInt(), data.consumeRemainingAsString())
    }

    private fun exploreMe(
        prefix: String,
        n: Int,
        suffix: String,
    ) {
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
