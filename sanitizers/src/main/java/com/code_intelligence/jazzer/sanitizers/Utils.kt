/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

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
    fun readBytes(stream: InputStream, size: Int): ByteArray {
        val current = ByteArray(size)
        var n = 0
        while (n < size) {
            val count = stream.read(current, n, size - n)
            if (count < 0) break
            n += count
        }
        return current
    }

    check(stream.markSupported())
    stream.mark(target.size)
    val current = readBytes(stream, target.size)
    stream.reset()
    Jazzer.guideTowardsEquality(current, target, id)
}
