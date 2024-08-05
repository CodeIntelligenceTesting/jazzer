/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor

import java.security.MessageDigest
import java.security.SecureRandom

// This RNG is resistant to collisions (even under XOR) but fully deterministic.
internal class DeterministicRandom(vararg contexts: String) {
    private val random = SecureRandom.getInstance("SHA1PRNG").apply {
        val contextHash = MessageDigest.getInstance("SHA-256").run {
            for (context in contexts) {
                update(context.toByteArray())
            }
            digest()
        }
        setSeed(contextHash)
    }

    fun nextInt(bound: Int) = random.nextInt(bound)

    fun nextInt() = random.nextInt()
}
