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

import java.io.IOException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object KotlinStringCompareFuzzer {
    @JvmStatic
    @OptIn(ExperimentalEncodingApi::class)
    fun fuzzerTestOneInput(data: ByteArray) {
        val text = Base64.encode(data)
        if (text.startsWith("aGVsbG8K") &&
            // hello
            text.endsWith("d29ybGQK") // world
        ) {
            throw IOException("Found the secret message!")
        }
    }
}
