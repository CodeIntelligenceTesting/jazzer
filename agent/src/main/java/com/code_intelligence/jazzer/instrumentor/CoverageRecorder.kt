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

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.runtime.CoverageMap
import com.code_intelligence.jazzer.third_party.jacoco.core.analysis.CoverageBuilder
import com.code_intelligence.jazzer.third_party.jacoco.core.data.ExecutionData
import com.code_intelligence.jazzer.third_party.jacoco.core.data.ExecutionDataReader
import com.code_intelligence.jazzer.third_party.jacoco.core.data.ExecutionDataStore
import com.code_intelligence.jazzer.third_party.jacoco.core.data.ExecutionDataWriter
import com.code_intelligence.jazzer.third_party.jacoco.core.data.SessionInfo
import com.code_intelligence.jazzer.third_party.jacoco.core.data.SessionInfoStore
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.data.CRC64
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import io.github.classgraph.ClassGraph
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.util.UUID

private data class InstrumentedClassInfo(
    val classId: Long,
    val initialEdgeId: Int,
    val nextEdgeId: Int,
    val bytecode: ByteArray,
)

object CoverageRecorder {
    var classNameGlobber = ClassNameGlobber(emptyList(), emptyList())
    private val instrumentedClassInfo = mutableMapOf<String, InstrumentedClassInfo>()
    private var startTimestamp: Instant? = null
    private val additionalCoverage = mutableSetOf<Int>()

    fun recordInstrumentedClass(internalClassName: String, bytecode: ByteArray, firstId: Int, numIds: Int) {
        if (startTimestamp == null)
            startTimestamp = Instant.now()
        instrumentedClassInfo[internalClassName] = InstrumentedClassInfo(
            CRC64.classId(bytecode), firstId, firstId + numIds, bytecode
        )
    }

    /**
     * Manually records coverage IDs based on the current state of [CoverageMap.mem].
     * Should be called after static initializers have run.
     */
    @JvmStatic
    fun updateCoveredIdsWithCoverageMap() {
        val mem = CoverageMap.mem
        val size = mem.capacity()
        additionalCoverage.addAll((0 until size).filter { mem[it] > 0 })
    }

    @JvmStatic
    fun replayCoveredIds() {
        val mem = CoverageMap.mem
        for (coverageId in additionalCoverage) {
            mem.put(coverageId, 1)
        }
    }

    @JvmStatic
    fun computeFileCoverage(coveredIds: IntArray): String {
        val coverage = analyzeCoverage(coveredIds.toSet()) ?: return "No classes were instrumented"
        return coverage.sourceFiles.joinToString(
            "\n",
            prefix = "Branch coverage:\n",
            postfix = "\n\n"
        ) { fileCoverage ->
            val counter = fileCoverage.branchCounter
            val percentage = 100 * counter.coveredRatio
            "${fileCoverage.name}: ${counter.coveredCount}/${counter.totalCount} (${percentage.format(2)}%)"
        } + coverage.sourceFiles.joinToString(
            "\n",
            prefix = "Line coverage:\n",
            postfix = "\n\n"
        ) { fileCoverage ->
            val counter = fileCoverage.lineCounter
            val percentage = 100 * counter.coveredRatio
            "${fileCoverage.name}: ${counter.coveredCount}/${counter.totalCount} (${percentage.format(2)}%)"
        } + coverage.sourceFiles.joinToString(
            "\n",
            prefix = "Incompletely covered lines:\n",
            postfix = "\n\n"
        ) { fileCoverage ->
            "${fileCoverage.name}: " + (fileCoverage.firstLine..fileCoverage.lastLine).filter {
                val instructions = fileCoverage.getLine(it).instructionCounter
                instructions.coveredCount in 1 until instructions.totalCount
            }.toString()
        } + coverage.sourceFiles.joinToString(
            "\n",
            prefix = "Missed lines:\n",
        ) { fileCoverage ->
            "${fileCoverage.name}: " + (fileCoverage.firstLine..fileCoverage.lastLine).filter {
                val instructions = fileCoverage.getLine(it).instructionCounter
                instructions.coveredCount == 0 && instructions.totalCount > 0
            }.toString()
        }
    }

    private fun Double.format(digits: Int) = "%.${digits}f".format(this)

    fun dumpJacocoCoverage(coveredIds: Set<Int>): ByteArray? {
        // Update the list of covered IDs with the coverage information for the current run.
        updateCoveredIdsWithCoverageMap()

        val dumpTimestamp = Instant.now()
        val outStream = ByteArrayOutputStream()
        val outWriter = ExecutionDataWriter(outStream)
        // Return null if no class has been instrumented.
        val startTimestamp = startTimestamp ?: return null
        outWriter.visitSessionInfo(
            SessionInfo(UUID.randomUUID().toString(), startTimestamp.epochSecond, dumpTimestamp.epochSecond)
        )

        val sortedCoveredIds = (additionalCoverage + coveredIds).sorted().toIntArray()
        for ((internalClassName, info) in instrumentedClassInfo) {
            // Determine the subarray of coverage IDs in sortedCoveredIds that contains the IDs generated while
            // instrumenting the current class. Since the ID array is sorted, use binary search.
            var coveredIdsStart = sortedCoveredIds.binarySearch(info.initialEdgeId)
            if (coveredIdsStart < 0) {
                coveredIdsStart = -(coveredIdsStart + 1)
            }
            var coveredIdsEnd = sortedCoveredIds.binarySearch(info.nextEdgeId)
            if (coveredIdsEnd < 0) {
                coveredIdsEnd = -(coveredIdsEnd + 1)
            }
            if (coveredIdsStart == coveredIdsEnd) {
                // No coverage data for the class.
                continue
            }
            check(coveredIdsStart in 0 until coveredIdsEnd && coveredIdsEnd <= sortedCoveredIds.size) {
                "Invalid range [$coveredIdsStart, $coveredIdsEnd) with coveredIds.size=${sortedCoveredIds.size}"
            }
            // Generate a probes array for the current class only, i.e., mapping info.initialEdgeId to 0.
            val probes = BooleanArray(info.nextEdgeId - info.initialEdgeId)
            (coveredIdsStart until coveredIdsEnd).asSequence()
                .map {
                    val globalEdgeId = sortedCoveredIds[it]
                    globalEdgeId - info.initialEdgeId
                }
                .forEach { classLocalEdgeId ->
                    probes[classLocalEdgeId] = true
                }
            outWriter.visitClassExecution(ExecutionData(info.classId, internalClassName, probes))
        }
        return outStream.toByteArray()
    }

    fun analyzeCoverage(coveredIds: Set<Int>): CoverageBuilder? {
        return try {
            val coverage = CoverageBuilder()
            analyzeAllUncoveredClasses(coverage)
            val rawExecutionData = dumpJacocoCoverage(coveredIds) ?: return null
            val executionDataStore = ExecutionDataStore()
            val sessionInfoStore = SessionInfoStore()
            ByteArrayInputStream(rawExecutionData).use { stream ->
                ExecutionDataReader(stream).run {
                    setExecutionDataVisitor(executionDataStore)
                    setSessionInfoVisitor(sessionInfoStore)
                    read()
                }
            }
            for ((internalClassName, info) in instrumentedClassInfo) {
                EdgeCoverageInstrumentor(0).analyze(
                    executionDataStore,
                    coverage,
                    info.bytecode,
                    internalClassName
                )
            }
            coverage
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Traverses the entire classpath and analyzes all uncovered classes that match the include/exclude pattern.
     * The returned [CoverageBuilder] will report coverage information for *all* classes on the classpath, not just
     * those that were loaded while the fuzzer ran.
     */
    private fun analyzeAllUncoveredClasses(coverage: CoverageBuilder): CoverageBuilder {
        val coveredClassNames = instrumentedClassInfo
            .keys
            .asSequence()
            .map { it.replace('/', '.') }
            .toSet()
        val emptyExecutionDataStore = ExecutionDataStore()
        ClassGraph()
            .enableClassInfo()
            .ignoreClassVisibility()
            .rejectPackages(
                // Always exclude Jazzer-internal packages (including ClassGraph itself) from coverage reports. Classes
                // from the Java standard library are never traversed.
                "com.code_intelligence.jazzer.*",
                "jaz",
            )
            .scan().use { result ->
                result.allClasses
                    .asSequence()
                    .filter { classInfo -> classNameGlobber.includes(classInfo.name) }
                    .filterNot { classInfo -> classInfo.name in coveredClassNames }
                    .forEach { classInfo ->
                        classInfo.resource.use { resource ->
                            EdgeCoverageInstrumentor(0).analyze(
                                emptyExecutionDataStore,
                                coverage,
                                resource.load(),
                                classInfo.name.replace('.', '/')
                            )
                        }
                    }
            }
        return coverage
    }
}
