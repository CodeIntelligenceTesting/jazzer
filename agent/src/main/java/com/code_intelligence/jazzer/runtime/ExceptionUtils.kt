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

@file:JvmName("ExceptionUtils")

package com.code_intelligence.jazzer.runtime

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow
import java.lang.management.ManagementFactory
import java.nio.ByteBuffer
import java.security.MessageDigest

private fun hash(throwable: Throwable, passToRootCause: Boolean): ByteArray =
    MessageDigest.getInstance("SHA-256").run {
        // It suffices to hash the stack trace of the deepest cause as the higher-level causes only
        // contain part of the stack trace (plus possibly a different exception type).
        var rootCause = throwable
        if (passToRootCause) {
            while (true) {
                rootCause = rootCause.cause ?: break
            }
        }
        update(rootCause.javaClass.name.toByteArray())
        for (element in rootCause.stackTrace) {
            update(element.toString().toByteArray())
        }
        if (throwable.suppressed.isNotEmpty()) {
            update("suppressed".toByteArray())
            for (suppressed in throwable.suppressed) {
                update(hash(suppressed, passToRootCause))
            }
        }
        digest()
    }

/**
 * Computes a hash of the stack trace of [throwable] without messages.
 *
 * The hash can be used to deduplicate stack traces obtained on crashes. By not including the
 * messages, this hash should not depend on the precise crashing input.
 */
fun computeDedupToken(throwable: Throwable): Long {
    var passToRootCause = true
    if (throwable is FuzzerSecurityIssueLow && throwable.cause is StackOverflowError) {
        // Special handling for StackOverflowErrors as processed by preprocessThrowable:
        // Only consider the repeated part of the stack trace and ignore the original stack trace in
        // the cause.
        passToRootCause = false
    }
    return ByteBuffer.wrap(hash(throwable, passToRootCause)).long
}

/**
 * Annotates [throwable] with a severity and additional information if it represents a bug type
 * that has security content.
 */
fun preprocessThrowable(throwable: Throwable): Throwable = when (throwable) {
    is StackOverflowError -> {
        // StackOverflowErrors are hard to deduplicate as the top-most stack frames vary wildly,
        // whereas the information that is most useful for deduplication detection is hidden in the
        // rest of the (truncated) stack frame.
        // We heuristically clean up the stack trace by taking the elements from the bottom and
        // stopping at the first repetition of a frame. The original error is returned as the cause
        // unchanged.
        val observedFrames = mutableSetOf<StackTraceElement>()
        val bottomFramesWithoutRepetition = throwable.stackTrace.takeLastWhile { frame ->
            (frame !in observedFrames).also { observedFrames.add(frame) }
        }
        FuzzerSecurityIssueLow("Stack overflow (use '${getReproducingXssArg()}' to reproduce)", throwable).apply {
            stackTrace = bottomFramesWithoutRepetition.toTypedArray()
        }
    }
    is OutOfMemoryError -> stripOwnStackTrace(
        FuzzerSecurityIssueLow(
            "Out of memory (use '${getReproducingXmxArg()}' to reproduce)", throwable
        )
    )
    is VirtualMachineError -> stripOwnStackTrace(FuzzerSecurityIssueLow(throwable))
    else -> throwable
}

/**
 * Strips the stack trace of [throwable] (e.g. because it was created in a utility method), but not
 * the stack traces of its causes.
 */
private fun stripOwnStackTrace(throwable: Throwable) = throwable.apply {
    stackTrace = emptyArray()
}

/**
 * Returns a valid `-Xmx` JVM argument that sets the stack size to a value with which [StackOverflowError] findings can
 * be reproduced, assuming the environment is sufficiently similar (e.g. OS and JVM version).
 */
private fun getReproducingXmxArg(): String? {
    val maxHeapSizeInMegaBytes = (getNumericFinalFlagValue("MaxHeapSize") ?: return null) shr 20
    val conservativeMaxHeapSizeInMegaBytes = (maxHeapSizeInMegaBytes * 0.9).toInt()
    return "-Xmx${conservativeMaxHeapSizeInMegaBytes}m"
}

/**
 * Returns a valid `-Xss` JVM argument that sets the stack size to a value with which [StackOverflowError] findings can
 * be reproduced, assuming the environment is sufficiently similar (e.g. OS and JVM version).
 */
private fun getReproducingXssArg(): String? {
    val threadStackSizeInKiloBytes = getNumericFinalFlagValue("ThreadStackSize") ?: return null
    val conservativeThreadStackSizeInKiloBytes = (threadStackSizeInKiloBytes * 0.9).toInt()
    return "-Xss${conservativeThreadStackSizeInKiloBytes}k"
}

private fun getNumericFinalFlagValue(arg: String): Long? {
    val argPattern = "$arg\\D*(\\d*)".toRegex()
    return argPattern.find(javaFullFinalFlags ?: return null)?.groupValues?.get(1)?.toLongOrNull()
}

private val javaFullFinalFlags by lazy {
    readJavaFullFinalFlags()
}

private fun readJavaFullFinalFlags(): String? {
    val javaHome = System.getProperty("java.home") ?: return null
    val javaBinary = "$javaHome/bin/java"
    val currentJvmArgs = ManagementFactory.getRuntimeMXBean().inputArguments
    val javaPrintFlagsProcess = ProcessBuilder(
        listOf(javaBinary) + currentJvmArgs + listOf(
            "-XX:+PrintFlagsFinal",
            "-version"
        )
    ).start()
    return javaPrintFlagsProcess.inputStream.bufferedReader().useLines { lineSequence ->
        lineSequence
            .filter { it.contains("ThreadStackSize") || it.contains("MaxHeapSize") }
            .joinToString("\n")
    }
}

fun dumpAllStackTraces() {
    System.err.println("\nStack traces of all JVM threads:\n")
    for ((thread, stack) in Thread.getAllStackTraces()) {
        System.err.println(thread)
        // Remove traces of this method and the methods it calls.
        stack.asList()
            .asReversed()
            .takeWhile {
                !(
                    it.className == "com.code_intelligence.jazzer.runtime.ExceptionUtils" &&
                        it.methodName == "dumpAllStackTraces"
                    )
            }
            .asReversed()
            .forEach { frame ->
                System.err.println("\tat $frame")
            }
        System.err.println()
    }
    System.err.println("Garbage collector stats:")
    System.err.println(
        ManagementFactory.getGarbageCollectorMXBeans().joinToString("\n", "\n", "\n") {
            "${it.name}: ${it.collectionCount} collections took ${it.collectionTime}ms"
        }
    )
}
