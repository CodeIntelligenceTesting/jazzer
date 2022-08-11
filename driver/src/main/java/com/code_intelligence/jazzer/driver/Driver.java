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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import net.bytebuddy.agent.ByteBuddyAgent;

public class Driver {
  // Accessed from jazzer_main.cpp.
  @SuppressWarnings("unused")
  private static int start(byte[][] nativeArgs) throws IOException {
    List<String> args = Utils.fromNativeArgs(nativeArgs);

    final boolean spawnsSubprocesses = args.stream().anyMatch(
        arg -> arg.startsWith("-fork=") || arg.startsWith("-jobs=") || arg.startsWith("-merge="));
    if (spawnsSubprocesses) {
      if (!System.getProperty("jazzer.coverage_report", "").isEmpty()) {
        err.println(
            "WARN: --coverage_report does not support parallel fuzzing and has been disabled");
        System.clearProperty("jazzer.coverage_report");
      }
      if (!System.getProperty("jazzer.coverage_dump", "").isEmpty()) {
        err.println(
            "WARN: --coverage_dump does not support parallel fuzzing and has been disabled");
        System.clearProperty("jazzer.coverage_dump");
      }

      String idSyncFileArg = System.getProperty("jazzer.id_sync_file", "");
      Path idSyncFile;
      if (idSyncFileArg.isEmpty()) {
        // Create an empty temporary file used for coverage ID synchronization and
        // pass its path to the agent in every child process. This requires adding
        // the argument to argv for it to be picked up by libFuzzer, which then
        // forwards it to child processes.
        idSyncFile = Files.createTempFile("jazzer-", "");
        args.add("--id_sync_file=" + idSyncFile.toAbsolutePath());
      } else {
        // Creates the file, truncating it if it exists.
        idSyncFile = Files.write(Paths.get(idSyncFileArg), new byte[] {});
      }
      idSyncFile.toFile().deleteOnExit();
    }

    // Jazzer's hooks use deterministic randomness and thus require a seed. Search for the last
    // occurrence of a "-seed" argument as that is the one that is used by libFuzzer. If none is
    // set, generate one and pass it to libFuzzer so that a fuzzing run can be reproduced simply by
    // setting the seed printed by libFuzzer.
    String seed =
        args.stream()
            .reduce(
                (prev, cur) -> cur.startsWith("-seed=") ? cur.substring("-seed=".length()) : prev)
            .orElseGet(() -> {
              String newSeed = Integer.toUnsignedString(new SecureRandom().nextInt());
              // Only add the -seed argument to the command line if not running in a mode
              // that spawns subprocesses. These would inherit the same seed, which might
              // make them less effective.
              if (spawnsSubprocesses) {
                args.add("-seed=" + newSeed);
              }
              return newSeed;
            });
    System.setProperty("jazzer.seed", seed);

    // Do *not* modify system properties beyond this point - initializing Opt parses them as a side
    // effect.

    if (Opt.hooks) {
      Agent.premain(Opt.agentArgs, ByteBuddyAgent.install());
    }

    return FuzzTargetRunner.startLibFuzzer(args);
  }
}
