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

package com.code_intelligence.jazzer.runtime

import java.nio.ByteBuffer
import java.security.MessageDigest

@Suppress("unused")
internal object Utils {

    private fun hash(throwable: Throwable): ByteArray = MessageDigest.getInstance("SHA-256").run {
        // It suffices to hash the stack trace of the deepest cause as the higher-level causes only
        // contain part of the stack trace (plus possibly a different exception type).
        var rootCause = throwable
        while (true) {
            rootCause = rootCause.cause ?: break
        }
        update(rootCause.javaClass.name.toByteArray())
        for (element in rootCause.stackTrace) {
            update(element.toString().toByteArray())
        }
        if (throwable.suppressed.isNotEmpty()) {
            update("suppressed".toByteArray())
            for (suppressed in throwable.suppressed) {
                update(hash(suppressed))
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
    @JvmStatic
    fun computeDedupToken(throwable: Throwable): Long {
        return ByteBuffer.wrap(hash(throwable)).long
    }
}
