/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example

import com.beust.klaxon.KlaxonException
import com.beust.klaxon.Parser
import com.code_intelligence.jazzer.api.FuzzedDataProvider

// Reproduces https://github.com/cbeust/klaxon/pull/330
object KlaxonFuzzer {

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        try {
            Parser.default().parse(StringBuilder(data.consumeRemainingAsString()))
        } catch (_: KlaxonException) {
        }
    }
}
