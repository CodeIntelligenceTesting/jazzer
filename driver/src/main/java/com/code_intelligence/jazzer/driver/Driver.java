/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.driver;

import static java.lang.System.err;

import com.code_intelligence.jazzer.agent.Agent;
import java.util.List;
import net.bytebuddy.agent.ByteBuddyAgent;

public class Driver {
  // Accessed from jazzer_main.cpp.
  @SuppressWarnings("unused")
  private static int start(byte[][] nativeArgs) {
    List<String> args = Utils.fromNativeArgs(nativeArgs);

    // Do *not* modify system properties beyond this point - initializing Opt parses them as a side
    // effect.

    if (Opt.hooks) {
      Agent.premain(Opt.agentArgs, ByteBuddyAgent.install());
    }

    return FuzzTargetRunner.startLibFuzzer(args);
  }
}
