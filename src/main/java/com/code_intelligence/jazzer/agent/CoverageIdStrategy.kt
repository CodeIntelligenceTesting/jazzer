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

package com.code_intelligence.jazzer.agent

import com.code_intelligence.jazzer.utils.Log
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.UUID

/**
 * Indicates a fatal failure to generate synchronized coverage IDs.
 */
class CoverageIdException(
    cause: Throwable? = null,
) : RuntimeException("Failed to synchronize coverage IDs", cause)

/**
 * [CoverageIdStrategy] provides an abstraction to switch between context specific coverage ID generation.
 *
 * Coverage (i.e., edge) IDs differ from other kinds of IDs, such as those generated for call sites or cmp
 * instructions, in that they should be consecutive, collision-free, and lie in a known, small range.
 * This precludes us from generating them simply as hashes of class names.
 */
interface CoverageIdStrategy {
    /**
     * [withIdForClass] provides the initial coverage ID of the given [className] as parameter to the
     * [block] to execute. [block] has to return the number of additionally used IDs.
     */
    @Throws(CoverageIdException::class)
    fun withIdForClass(
        className: String,
        block: (Int) -> Int,
    )
}

/**
 * A memory synced strategy for coverage ID generation.
 *
 * This strategy uses a synchronized block to guard access to a global edge ID counter.
 * Even though concurrent fuzzing is not fully supported this strategy enables consistent coverage
 * IDs in case of concurrent class loading.
 *
 * It only prevents races within one VM instance.
 */
class MemSyncCoverageIdStrategy : CoverageIdStrategy {
    private var nextEdgeId = 0

    @Synchronized
    override fun withIdForClass(
        className: String,
        block: (Int) -> Int,
    ) {
        nextEdgeId += block(nextEdgeId)
    }
}

/**
 * A strategy for coverage ID generation that synchronizes the IDs assigned to a class with other processes via the
 * specified [idSyncFile].
 * This class takes care of synchronizing the access to the file between multiple processes as long as the general
 * contract of [CoverageIdStrategy] is followed.
 */
class FileSyncCoverageIdStrategy(
    private val idSyncFile: Path,
) : CoverageIdStrategy {
    private val uuid: UUID = UUID.randomUUID()
    private var idFileLock: FileLock? = null

    private var cachedFirstId: Int? = null
    private var cachedClassName: String? = null
    private var cachedIdCount: Int? = null

    /**
     * This method is synchronized to prevent concurrent access to the internal file lock which would result in
     * [java.nio.channels.OverlappingFileLockException]. Furthermore, every coverage ID obtained by [obtainFirstId]
     * is always committed back again to the sync file by [commitIdCount].
     */
    @Synchronized
    override fun withIdForClass(
        className: String,
        block: (Int) -> Int,
    ) {
        var actualNumEdgeIds = 0
        try {
            val firstId = obtainFirstId(className)
            actualNumEdgeIds = block(firstId)
        } finally {
            commitIdCount(actualNumEdgeIds)
        }
    }

    /**
     * Obtains a coverage ID for [className] such that all cooperating agent processes will obtain the same ID.
     * There are two cases to consider:
     * - This agent process is the first to encounter [className], i.e., it does not find a record for that class in
     *   [idSyncFile]. In this case, a lock on the file is held until the class has been instrumented and a record with
     *   the required number of coverage IDs has been added.
     * - Another agent process has already encountered [className], i.e., there is a record that class in [idSyncFile].
     *   In this case, the lock on the file is returned immediately and the extracted first coverage ID is returned to
     *   the caller. The caller is still expected to call [commitIdCount] so that desynchronization can be detected.
     */
    private fun obtainFirstId(className: String): Int {
        try {
            check(idFileLock == null) { "Already holding a lock on the ID file" }
            val localIdFile =
                FileChannel.open(
                    idSyncFile,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.READ,
                )
            // Wait until we have obtained the lock on the sync file. We hold the lock from this point until we have
            // finished reading and writing (if necessary) to the file.
            val localIdFileLock = localIdFile.lock()
            check(localIdFileLock.isValid && !localIdFileLock.isShared)
            // Parse the sync file, which consists of lines of the form
            // <class name>:<first ID>:<num IDs>
            val idInfo =
                localIdFileLock
                    .channel()
                    .readFully()
                    .lineSequence()
                    .filterNot { it.isBlank() }
                    .map { line ->
                        val parts = line.split(':')
                        check(parts.size == 4) {
                            "Expected ID file line to be of the form  '<class name>:<first ID>:<num IDs>:<uuid>', got '$line'"
                        }
                        val lineClassName = parts[0]
                        val lineFirstId = parts[1].toInt()
                        check(lineFirstId >= 0) { "Negative first ID in line: $line" }
                        val lineIdCount = parts[2].toInt()
                        check(lineIdCount >= 0) { "Negative ID count in line: $line" }
                        Triple(lineClassName, lineFirstId, lineIdCount)
                    }.toList()
            cachedClassName = className
            val idInfoForClass = idInfo.filter { it.first == className }
            return when (idInfoForClass.size) {
                0 -> {
                    // We are the first to encounter this class and thus need to hold the lock until the class has been
                    // instrumented and we know the required number of coverage IDs.
                    idFileLock = localIdFileLock
                    // Compute the next free ID as the maximum over the sums of first ID and ID count, starting at 0 if
                    // this is the first ID to be assigned. In fact, since this is the only way new lines are added to
                    // the file, the maximum is always attained by the last line.
                    val nextFreeId = idInfo.asSequence().map { it.second + it.third }.lastOrNull() ?: 0
                    cachedFirstId = nextFreeId
                    nextFreeId
                }
                1 -> {
                    // This class has already been instrumented elsewhere, so we just return the first ID and ID count
                    // reported from there and release the lock right away. The caller is still expected to call
                    // commitIdCount.
                    localIdFile.close()
                    cachedIdCount = idInfoForClass.single().third
                    idInfoForClass.single().second
                }
                else -> {
                    localIdFile.close()
                    Log.println(idInfo.joinToString("\n") { "${it.first}:${it.second}:${it.third}" })
                    throw IllegalStateException("Multiple entries for $className in ID file")
                }
            }
        } catch (e: Exception) {
            throw CoverageIdException(e)
        }
    }

    /**
     * Records the number of coverage IDs used to instrument the class specified in a previous call to [obtainFirstId].
     * If instrumenting the class should fail, this function must still be called. In this case, [idCount] is set to 0.
     */
    private fun commitIdCount(idCount: Int) {
        val localIdFileLock = idFileLock
        try {
            check(cachedClassName != null)
            if (localIdFileLock == null) {
                // We released the lock already in obtainFirstId since the class had already been instrumented
                // elsewhere. As we know the expected number of IDs for the current class in this case, check for
                // deviations.
                check(cachedIdCount != null)
                check(idCount == cachedIdCount) {
                    "$cachedClassName has $idCount edges, but $cachedIdCount edges reserved in ID file"
                }
            } else {
                // We are the first to instrument this class and should record the number of IDs in the sync file.
                check(cachedFirstId != null)
                localIdFileLock.channel().append("$cachedClassName:$cachedFirstId:$idCount:$uuid\n")
                localIdFileLock.channel().force(true)
            }
            idFileLock = null
            cachedFirstId = null
            cachedIdCount = null
            cachedClassName = null
        } catch (e: Exception) {
            throw CoverageIdException(e)
        } finally {
            localIdFileLock?.channel()?.close()
        }
    }
}

/**
 * Reads the [FileChannel] to the end as a UTF-8 string.
 */
fun FileChannel.readFully(): String {
    check(size() <= Int.MAX_VALUE)
    val buffer = ByteBuffer.allocate(size().toInt())
    while (buffer.hasRemaining()) {
        when (read(buffer)) {
            0 -> throw IllegalStateException("No bytes read")
            -1 -> break
        }
    }
    return String(buffer.array())
}

/**
 * Appends [string] to the end of the [FileChannel].
 */
fun FileChannel.append(string: String) {
    position(size())
    write(ByteBuffer.wrap(string.toByteArray()))
}
