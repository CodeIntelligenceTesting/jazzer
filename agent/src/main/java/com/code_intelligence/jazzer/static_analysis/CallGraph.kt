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

import soot.Scene

fun computeCallGraph(fuzzTargetClass: String, callGraphBasepath: String) {
    SootConfigurator.configure()

    Scene.v().apply {
        loadClassAndSupport(fuzzTargetClass)
        loadNecessaryClasses()
    }

    // Set the fuzz target as the sole entrypoint for the call graph generation.
    val targetClass = Scene.v().classes.single { it.name == fuzzTargetClass }
    val targetMethod = targetClass.getMethodByName("fuzzerTestOneInput")
    Scene.v().apply {
        entryPoints = listOf(targetMethod)
    }

    SootCallGraphComputer.compute(CallGraphAlgorithm.CHA)

    SootJazzerCFGIdMapper().compute(callGraphBasepath)
}
