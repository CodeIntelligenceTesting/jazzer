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

    private fun encrypt(n: Long): Long = n.xor(0x1122334455667788)
}
