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

import soot.PackManager
import soot.Scene
import soot.options.Options

object SootCallGraphComputer {

    fun compute(callGraphAlgorithm: CallGraphAlgorithm) {
        configure(callGraphAlgorithm)
        PackManager.v().apply {
            getPack(SootPhase.CG.string).apply()
            runBodyPacks()
        }
        check(Scene.v().hasCallGraph())
    }

    private fun configure(callGraphAlgorithm: CallGraphAlgorithm) {
        Options.v().apply {
            when (callGraphAlgorithm) {
                CallGraphAlgorithm.CHA -> setPhaseOption(SootPhase.CG_CHA.string, "on")
                CallGraphAlgorithm.RTA -> {
                    setPhaseOption(SootPhase.CG_SPARK.string, "on")
                    setPhaseOption(SootPhase.CG_SPARK.string, "rta:true")
                    setPhaseOption(SootPhase.CG_SPARK.string, "on-fly-cg:false")
                }
                CallGraphAlgorithm.VTA -> {
                    setPhaseOption(SootPhase.CG_SPARK.string, "on")
                    setPhaseOption(SootPhase.CG_SPARK.string, "vta:true")
                    setPhaseOption(SootPhase.CG_SPARK.string, "on-fly-cg:false")
                }
                CallGraphAlgorithm.SPARK -> setPhaseOption(SootPhase.CG_SPARK.string, "on")
                CallGraphAlgorithm.SPARK_LIBRARY -> {
                    setPhaseOption(SootPhase.CG_SPARK.string, "on")
                    setPhaseOption(SootPhase.CG.string, "library:any-subtype")
                }
            }
        }
    }
}
