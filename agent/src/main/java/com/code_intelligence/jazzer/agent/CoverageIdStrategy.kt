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

package com.code_intelligence.jazzer.agent

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * Indicates a fatal failure to generate synchronized coverage IDs.
 */
internal class CoverageIdException(cause: Throwable? = null) :
    RuntimeException("Failed to synchronize coverage IDs", cause)

interface CoverageIdStrategy {
    /**
     * Obtain the first coverage ID to be used for the class [className].
     * The caller *must* also call [commitIdCount] once it has instrumented that class, even if instrumentation fails.
     */
    @Throws(CoverageIdException::class)
    fun obtainFirstId(className: String): Int

    /**
     * Records the number of coverage IDs used to instrument the class specified in a previous call to [obtainFirstId].
     * If instrumenting the class should fail, this function must still be called. In this case, [idCount] is set to 0.
     */
    @Throws(CoverageIdException::class)
    fun commitIdCount(idCount: Int)
}

/**
 * An unsynchronized strategy for coverage ID generation that simply increments a global counter.
 */
internal class TrivialCoverageIdStrategy : CoverageIdStrategy {
    private var nextEdgeId = 0

    override fun obtainFirstId(className: String) = nextEdgeId

    override fun commitIdCount(idCount: Int) {
        nextEdgeId += idCount
    }
}

