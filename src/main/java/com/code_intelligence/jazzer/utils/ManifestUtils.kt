/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils

import java.util.jar.Manifest

object ManifestUtils {

    private const val FUZZ_TARGET_CLASS = "Jazzer-Fuzz-Target-Class"
    const val HOOK_CLASSES = "Jazzer-Hook-Classes"

    fun combineManifestValues(attribute: String): List<String> {
        val manifests = ManifestUtils::class.java.classLoader.getResources("META-INF/MANIFEST.MF")
        return manifests.asSequence().mapNotNull { url ->
            url.openStream().use { inputStream ->
                val manifest = Manifest(inputStream)
                manifest.mainAttributes.getValue(attribute)
            }
        }.toList()
    }

    /**
     * Returns the value of the `Fuzz-Target-Class` manifest attribute if there is a unique one among all manifest
     * files in the classpath.
     */
    @JvmStatic
    fun detectFuzzTargetClass(): String? {
        val fuzzTargets = combineManifestValues(FUZZ_TARGET_CLASS)
        return when (fuzzTargets.size) {
            0 -> null
            1 -> fuzzTargets.first()
            else -> {
                Log.warn("More than one Jazzer-Fuzz-Target-Class manifest entry detected on the classpath.")
                null
            }
        }
    }
}
