// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.static_analysis

import org.jgrapht.Graphs
import org.jgrapht.graph.DefaultDirectedGraph
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.nio.dot.DOTExporter
import org.jgrapht.nio.json.JSONExporter
import soot.Scene
import soot.SootMethod
import soot.Unit
import soot.jimple.AssignStmt
import soot.jimple.GotoStmt
import soot.jimple.InvokeStmt
import soot.jimple.Stmt
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG
import java.io.File
import java.util.Stack
import kotlin.collections.ArrayList

fun Unit.uniqueString(): String {
    return if (this.isMarker())
        (this as Stmt).invokeExpr.args.single().toString()
    else "<${this.hashCode()}>"
}

fun Unit.method(): SootMethod? {
    return try {
        (this as Stmt).invokeExpr.method
    } catch (e: RuntimeException) {
        null
    }
}

fun Unit.isMarker(): Boolean {
    // if it's not a method -> null != true as well
    return this.method()?.isMarker() == true
}

fun SootMethod.isMarker(): Boolean {
    return this.signature.equals("<java.nio.ByteBuffer: byte get(int)>")
}

fun SootMethod.isCall(): Boolean {
    return this.hasActiveBody() && !this.isJavaLibraryMethod
}

fun <V, E> DefaultDirectedGraph<V, E>.forceAddEdge(sourceVertex: V, targetVertex: V) {
    this.addVertex(sourceVertex)
    this.addVertex(targetVertex)
    this.addEdge(sourceVertex, targetVertex)
}

fun <V, E> DefaultDirectedGraph<V, E>.preds(vert: V): MutableList<V> {
    return Graphs.predecessorListOf(this, vert)!!
}

fun <V, E> DefaultDirectedGraph<V, E>.succs(vert: V): MutableList<V> {
    return Graphs.successorListOf(this, vert)!!
}

fun <E> DefaultDirectedGraph<Unit, E>.simplify() {
    this.vertexSet()
        .filter { !it.isMarker() }
        .forEach { n ->
            // redirect edges
            this.preds(n).forEach { pred ->
                this.succs(n).forEach { succ ->
                    this.addEdge(pred, succ)
                }
            }
            // remove node along its induced edges
            this.removeVertex(n)
        }
}

class SootJazzerCFGIdMapper {
    val outputGraph = DefaultDirectedGraph<Unit, DefaultEdge>(DefaultEdge::class.java)
    val visited = ArrayList<Unit>()

    /**
     * Traverses ICFG using Depth First Search and provides a pruned graph.
     *
     * When a Jazzer code coverage instrumentation pattern is found, the statements
     * after get(int) until put(int, byte) are ignored. The successor of put()
     * becomes the new successor for get().
     *
     */
    private fun getJazzerIds(
        icfg: JimpleBasedInterproceduralCFG,
        m: SootMethod
    ): MutableList<Unit> {
        val stackToBeProcessed = Stack<Unit>()
        stackToBeProcessed.addAll(icfg.getStartPointsOf(m))

        var fromUnit: Unit
        var succSrc: Unit

        //while we have unvisited nodes
        while (stackToBeProcessed.isNotEmpty()) {

            // pop elem from the stack
            val currentUnit = stackToBeProcessed.pop()
            if (currentUnit in visited) {
                // already processed
                continue
            }
            visited.add(currentUnit)

            // initialize pointers, might be overwritten when calling functions
            // we need two variables when we want to skip edges. e.g. we would like to calculate
            fromUnit = currentUnit
            succSrc = currentUnit

            // start processing
            if (icfg.isCallStmt(currentUnit)) {
                val method = currentUnit.method()!!

                if (method.isMarker()) {
                    // if it's a coverage marker
                    // consume all statements until we reach the "put" statement which marks the end of the coverage marker
                    var currentId = succSrc
                    do {
                        // the filtering will ignore all statements that we do not expect in the successors
                        // This will remove atCaughtException jumps
                        currentId = icfg.getSuccsOf(currentId).single { it is AssignStmt || it is InvokeStmt }
                    } while (!icfg.isCallStmt(currentId))

                    // adds successors to graph and stack
                    succSrc = currentId
                } else if (method.isCall()) {
                    // process the recursive calls
                    // only process methods that are defined by the user and not part of the std library

                    // @oshando: its unclear why there can be multiple startpoints,
                    // but the signature indicates that this could be possible
                    for (startPoint in icfg.getStartPointsOf(method)) {
                        outputGraph.forceAddEdge(currentUnit, startPoint)
                    }

                    getJazzerIds(icfg, method)

                    // mark return node of the function as source for new edges
                    fromUnit = visited.last()
                }
            }

            // add successors to the stack and the graph
            for (successor in icfg.getSuccsOf(succSrc)) {
                if (!visited.contains(successor)) {
                    // add edge to successor and push it to stack
                    stackToBeProcessed.push(successor)
                    outputGraph.forceAddEdge(fromUnit, successor)
                } else if (succSrc is GotoStmt) {
                    outputGraph.forceAddEdge(succSrc, successor)
                }
            }
        }
        return visited
    }

    /**
     * Extracts the code coverage instrumentation information of Jazzer and
     * maps them to Soot CFG/CallGraph
     *
     * Jazzer code coverage instrumentation pattern:
     * * $stack3 = virtualinvoke l1.<java.nio.ByteBuffer: byte get(int)>(0)
     * * $stack4 = $stack3 & 255
     * * $stack5 = $stack4 + 1
     * * $stack6 = $stack5 >> 8
     * * $stack7 = $stack5 + $stack6
     * * tmp = (byte) $stack7
     * * virtualinvoke l1.<java.nio.ByteBuffer: java.nio.ByteBuffer put(int,byte)>(0, tmp);
     *
     */
    fun compute(callGraphBasepath: String) {
        val icfg = JimpleBasedInterproceduralCFG()

        if (Scene.v().entryPoints.isNotEmpty()) {
            for (entryPoint in Scene.v().entryPoints) {
                println("INFO: Visiting entry point: ${entryPoint.signature}")
                
                getJazzerIds(icfg, entryPoint)

                outputGraph.simplify()
                val exporter = DOTExporter<Unit, DefaultEdge> { v -> "\"${v.uniqueString()}\"" }
                exporter.exportGraph(outputGraph, File("$callGraphBasepath.dot"))

                val exporter2 = JSONExporter<Unit, DefaultEdge> { it.uniqueString() }
                exporter2.exportGraph(outputGraph, File("$callGraphBasepath.json"))

                println("INFO: Created ICFG")
            }
        }
    }
}
