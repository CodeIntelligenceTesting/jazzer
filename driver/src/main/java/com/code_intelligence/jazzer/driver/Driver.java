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
      // This wouldn't run in case we exit the process with _Exit, but the parent process of a -fork
      // run is expected to exit with a regular exit(0), which does cause JVM shutdown hooks to run:
      // https://github.com/llvm/llvm-project/blob/940e178c0018b32af2f1478d331fc41a92a7dac7/compiler-rt/lib/fuzzer/FuzzerFork.cpp#L491
      idSyncFile.toFile().deleteOnExit();
    }

    // Jazzer's hooks use deterministic randomness and thus require a seed. Search for the last
    // occurrence of a "-seed" argument as that is the one that is used by libFuzzer. If none is
    // set, generate one and pass it to libFuzzer so that a fuzzing run can be reproduced simply by
    // setting the seed printed by libFuzzer.
    String seed = args.stream().reduce(
        null, (prev, cur) -> cur.startsWith("-seed=") ? cur.substring("-seed=".length()) : prev);
    if (seed == null) {
      seed = Integer.toUnsignedString(new SecureRandom().nextInt());
      // Only add the -seed argument to the command line if not running in a mode
      // that spawns subprocesses. These would inherit the same seed, which might
      // make them less effective.
      if (!spawnsSubprocesses) {
        args.add("-seed=" + seed);
      }
    }
    System.setProperty("jazzer.seed", seed);

    if (args.stream().noneMatch(arg -> arg.startsWith("-rss_limit_mb="))) {
      args.add(getDefaultRssLimitMbArg());
    }

    // Do *not* modify system properties beyond this point - initializing Opt parses them as a side
    // effect.

    if (Opt.hooks) {
      Agent.premain(null, ByteBuddyAgent.install());
    }

    return FuzzTargetRunner.startLibFuzzer(args);
  }

  private static String getDefaultRssLimitMbArg() {
    // Java OutOfMemoryErrors are strictly more informative than libFuzzer's out of memory crashes.
    // We thus want to scale the default libFuzzer memory limit, which includes all memory used by
    // the process including Jazzer's native and non-native memory footprint, such that:
    // 1. we never reach it purely by allocating memory on the Java heap;
    // 2. it is still reached if the fuzz target allocates excessively on the native heap.
    // As a heuristic, we set the overall memory limit to 2 * the maximum size of the Java heap and
    // add a fixed 1 GiB on top for the fuzzer's own memory usage.
    long maxHeapInBytes = Runtime.getRuntime().maxMemory();
    return "-rss_limit_mb=" + ((2 * maxHeapInBytes / (1024 * 1024)) + 1024);
  }
}
