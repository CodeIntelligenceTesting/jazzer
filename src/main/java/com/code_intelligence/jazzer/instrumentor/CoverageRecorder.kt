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

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.runtime.CoverageMap
import com.code_intelligence.jazzer.third_party.org.jacoco.core.analysis.CoverageBuilder
import com.code_intelligence.jazzer.third_party.org.jacoco.core.data.ExecutionData
import com.code_intelligence.jazzer.third_party.org.jacoco.core.data.ExecutionDataStore
import com.code_intelligence.jazzer.third_party.org.jacoco.core.data.ExecutionDataWriter
import com.code_intelligence.jazzer.third_party.org.jacoco.core.data.SessionInfo
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.data.CRC64
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import io.github.classgraph.ClassGraph
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
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

    fun recordInstrumentedClass(
        internalClassName: String,
        bytecode: ByteArray,
        firstId: Int,
        numIds: Int,
    ) {
        if (startTimestamp == null) {
            startTimestamp = Instant.now()
        }
        instrumentedClassInfo[internalClassName] =
            InstrumentedClassInfo(
                CRC64.classId(bytecode),
                firstId,
                firstId + numIds,
                bytecode,
            )
    }

    /**
     * Manually records coverage IDs based on the current state of [CoverageMap].
     * Should be called after static initializers have run.
     */
    @JvmStatic
    fun updateCoveredIdsWithCoverageMap() {
        additionalCoverage.addAll(CoverageMap.getCoveredIds())
    }

    /**
     * [dumpCoverageReport] dumps a human-readable coverage report of files using any [coveredIds] to [dumpFileName].
     */
    @JvmStatic
    @JvmOverloads
    fun dumpCoverageReport(
        dumpFileName: String,
        coveredIds: IntArray = CoverageMap.getEverCoveredIds(),
    ) {
        File(dumpFileName).bufferedWriter().use { writer ->
            writer.write(computeFileCoverage(coveredIds))
        }
    }

    private fun computeFileCoverage(coveredIds: IntArray): String {
        fun Double.format(digits: Int) = "%.${digits}f".format(this)
        val coverage = analyzeCoverage(coveredIds.toSet()) ?: return "No classes were instrumented"
        return coverage.sourceFiles.joinToString(
            "\n",
            prefix = "Branch coverage:\n",
            postfix = "\n\n",
        ) { fileCoverage ->
            val counter = fileCoverage.branchCounter
            val percentage = 100 * counter.coveredRatio
            "${fileCoverage.name}: ${counter.coveredCount}/${counter.totalCount} (${percentage.format(2)}%)"
        } +
            coverage.sourceFiles.joinToString(
                "\n",
                prefix = "Line coverage:\n",
                postfix = "\n\n",
            ) { fileCoverage ->
                val counter = fileCoverage.lineCounter
                val percentage = 100 * counter.coveredRatio
                "${fileCoverage.name}: ${counter.coveredCount}/${counter.totalCount} (${percentage.format(2)}%)"
            } +
            coverage.sourceFiles.joinToString(
                "\n",
                prefix = "Incompletely covered lines:\n",
                postfix = "\n\n",
            ) { fileCoverage ->
                "${fileCoverage.name}: " +
                    (fileCoverage.firstLine..fileCoverage.lastLine)
                        .filter {
                            val instructions = fileCoverage.getLine(it).instructionCounter
                            instructions.coveredCount in 1 until instructions.totalCount
                        }.toString()
            } +
            coverage.sourceFiles.joinToString(
                "\n",
                prefix = "Missed lines:\n",
            ) { fileCoverage ->
                "${fileCoverage.name}: " +
                    (fileCoverage.firstLine..fileCoverage.lastLine)
                        .filter {
                            val instructions = fileCoverage.getLine(it).instructionCounter
                            instructions.coveredCount == 0 && instructions.totalCount > 0
                        }.toString()
            }
    }

    /**
     * [dumpJacocoCoverage] dumps the JaCoCo coverage of files using any [coveredIds] to [dumpFileName].
     * JaCoCo only exports coverage for files containing at least one coverage data point. The dump
     * can be used by the JaCoCo report command to create reports also including not covered files.
     */
    @JvmStatic
    @JvmOverloads
    fun dumpJacocoCoverage(
        dumpFileName: String,
        coveredIds: IntArray = CoverageMap.getEverCoveredIds(),
    ) {
        FileOutputStream(dumpFileName).use { outStream ->
            dumpJacocoCoverage(outStream, coveredIds)
        }
    }

    /**
     * [dumpJacocoCoverage] dumps the JaCoCo coverage of files using any [coveredIds] to [outStream].
     */
    @JvmStatic
    fun dumpJacocoCoverage(
        outStream: OutputStream,
        coveredIds: IntArray,
    ) {
        // Return if no class has been instrumented.
        val startTimestamp = startTimestamp ?: return

        // Update the list of covered IDs with the coverage information for the current run.
        updateCoveredIdsWithCoverageMap()

        val dumpTimestamp = Instant.now()
        val outWriter = ExecutionDataWriter(outStream)
        outWriter.visitSessionInfo(
            SessionInfo(UUID.randomUUID().toString(), startTimestamp.epochSecond, dumpTimestamp.epochSecond),
        )
        analyzeJacocoCoverage(coveredIds.toSet()).accept(outWriter)
    }

    /**
     * Build up a JaCoCo [ExecutionDataStore] based on [coveredIds] containing the internally gathered coverage information.
     */
    private fun analyzeJacocoCoverage(coveredIds: Set<Int>): ExecutionDataStore {
        val executionDataStore = ExecutionDataStore()
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
            (coveredIdsStart until coveredIdsEnd)
                .asSequence()
                .map {
                    val globalEdgeId = sortedCoveredIds[it]
                    globalEdgeId - info.initialEdgeId
                }.forEach { classLocalEdgeId ->
                    probes[classLocalEdgeId] = true
                }
            executionDataStore.visitClassExecution(ExecutionData(info.classId, internalClassName, probes))
        }
        return executionDataStore
    }

    /**
     * Create a [CoverageBuilder] containing all classes matching the include/exclude pattern and their coverage statistics.
     */
    fun analyzeCoverage(coveredIds: Set<Int>): CoverageBuilder? =
        try {
            val coverage = CoverageBuilder()
            analyzeAllUncoveredClasses(coverage)
            val executionDataStore = analyzeJacocoCoverage(coveredIds)
            for ((internalClassName, info) in instrumentedClassInfo) {
                EdgeCoverageInstrumentor(ClassInstrumentor.defaultEdgeCoverageStrategy, ClassInstrumentor.defaultCoverageMap, 0)
                    .analyze(
                        executionDataStore,
                        coverage,
                        info.bytecode,
                        internalClassName,
                    )
            }
            coverage
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }

    /**
     * Traverses the entire classpath and analyzes all uncovered classes that match the include/exclude pattern.
     * The returned [CoverageBuilder] will report coverage information for *all* classes on the classpath, not just
     * those that were loaded while the fuzzer ran.
     */
    private fun analyzeAllUncoveredClasses(coverage: CoverageBuilder): CoverageBuilder {
        val coveredClassNames =
            instrumentedClassInfo
                .keys
                .asSequence()
                .map { it.replace('/', '.') }
                .toSet()
        ClassGraph()
            .enableClassInfo()
            .ignoreClassVisibility()
            .rejectPackages(
                // Always exclude Jazzer-internal packages (including ClassGraph itself) from coverage reports. Classes
                // from the Java standard library are never traversed.
                "com.code_intelligence.jazzer.*",
                "jaz",
            ).scan()
            .use { result ->
                // ExecutionDataStore is used to look up existing coverage during analysis of the class files,
                // no entries are added during that. Passing in an empty store is fine for uncovered files.
                val emptyExecutionDataStore = ExecutionDataStore()
                result.allClasses
                    .asSequence()
                    .filter { classInfo -> classNameGlobber.includes(classInfo.name) }
                    .filterNot { classInfo -> classInfo.name in coveredClassNames }
                    .forEach { classInfo ->
                        classInfo.resource.use { resource ->
                            EdgeCoverageInstrumentor(
                                ClassInstrumentor.defaultEdgeCoverageStrategy,
                                ClassInstrumentor.defaultCoverageMap,
                                0,
                            ).analyze(
                                emptyExecutionDataStore,
                                coverage,
                                resource.load(),
                                classInfo.name.replace('.', '/'),
                            )
                        }
                    }
            }
        return coverage
    }
}
