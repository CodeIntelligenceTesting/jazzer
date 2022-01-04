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

import soot.G
import soot.SourceLocator
import soot.options.Options

object SootConfigurator {

    fun configure() {
        // Reset global Soot state.
        G.reset()
        // FIXME: Find out if this actually adds any value.
//        BoomerangPretransformer.v().reset()
        Options.v().apply {
            set_whole_program(true)
            set_keep_line_number(true)
            set_no_bodies_for_excluded(true)
            set_allow_phantom_refs(true)
            set_output_format(Options.output_format_none)
            set_exclude(excludedPackages)
            set_prepend_classpath(true)
            setPhaseOption(SootPhase.CG_CHA.string, "on")
            setPhaseOption(SootPhase.CG.string, "all-reachable:true")
            setPhaseOption(SootPhase.JB.string, "use-original-names:true")
            setPhaseOption(SootPhase.JOP.string, "enabled:true")
        }
        // Instead of specifying a Soot classpath, load all classes on demand with Jazzer's instrumentation applied.
        SourceLocator.v().setClassProviders(listOf(InstrumentedClassProvider))
    }

    private val excludedPackages = listOf(
        "sun.*",
        "java.*",
        "jdk.*",
        "com.sun.*",
        "com.ibm.*",
        "org.xml.*",
        "org.w3c.*",
        "apple.awt.*",
        "com.apple.*",
        "org.apache.jasper.*",
        "org.apache.el.*",
        "org.apache.tomcat.*",
        "org.apache.tools.*",
        "org.apache.juli.*",
        "org.eclipse.*",
        "com.code_intelligence.jazzer.*",
    )
}
