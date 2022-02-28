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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.Jazzer
import java.io.InputStream

/**
 * jaz.Zer is a honeypot class: All of its methods report a finding when called.
 */
const val HONEYPOT_CLASS_NAME = "jaz.Zer"
const val HONEYPOT_LIBRARY_NAME = "jazzer_honeypot"

internal fun Short.toBytes(): ByteArray {
    return byteArrayOf(
        ((toInt() shr 8) and 0xFF).toByte(),
        (toInt() and 0xFF).toByte(),
    )
}

// Runtime is only O(size * needle.size), only use for small arrays.
internal fun ByteArray.indexOf(needle: ByteArray): Int {
    outer@ for (i in 0 until size - needle.size + 1) {
        for (j in needle.indices) {
            if (this[i + j] != needle[j]) {
                continue@outer
            }
        }
        return i
    }
    return -1
}

internal fun guideMarkableInputStreamTowardsEquality(stream: InputStream, target: ByteArray, id: Int) {
    check(stream.markSupported())
    stream.mark(target.size)
    val current = stream.readNBytes(target.size)
    stream.reset()
    Jazzer.guideTowardsEquality(current, target, id)
}
