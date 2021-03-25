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
        FuzzerSecurityIssueLow("Stack overflow (truncated to likely cause)", throwable).apply {
            stackTrace = bottomFramesWithoutRepetition.toTypedArray()
        }
    }
    // Includes OutOfMemoryError
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
