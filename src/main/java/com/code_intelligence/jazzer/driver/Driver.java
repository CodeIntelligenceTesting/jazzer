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

package com.code_intelligence.jazzer.driver;

import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;
import static java.lang.System.exit;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.agent.AgentInstaller;
import com.code_intelligence.jazzer.driver.junit.JUnitRunner;
import com.code_intelligence.jazzer.utils.Log;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

public class Driver {
  public static int start(List<String> args, boolean spawnsSubprocesses) throws IOException {
    Log.debug("User: " + System.getProperty("user.name"));
    Log.debug("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
    Log.debug("Version: " + System.getProperty("java.runtime.version"));
    Log.debug("JAVA_HOME: " + System.getProperty("java.home"));
    Log.debug("Command line: " + String.join(" ", args));
    Log.debug("Classpath: " + System.getProperty("java.class.path"));
    Log.debug(
        "JAZZER environment variables: "
            + System.getenv().entrySet().stream()
                .filter(e -> e.getKey().startsWith("JAZZER_"))
                .collect(toList()));

    if (IS_ANDROID) {
      if (!Opt.autofuzz.get().isEmpty()) {
        Log.error("--autofuzz is not supported on Android");
        return 1;
      }
      if (!Opt.coverageReport.get().isEmpty()) {
        Log.error("--coverage_report is not supported on Android");
        return 1;
      }
      if (!Opt.coverageDump.get().isEmpty()) {
        Log.error("--coverage_dump is not supported on Android");
        return 1;
      }
    }

    if (spawnsSubprocesses) {
      if (!Opt.coverageReport.get().isEmpty()) {
        Log.error("--coverage_report is not supported with -fork, -jobs, or -merge");
        return 1;
      }
      if (!Opt.coverageDump.get().isEmpty()) {
        Log.error("--coverage_report is not supported with -fork, -jobs, or -merge");
        return 1;
      }

      String idSyncFileArg = Opt.idSyncFile.get();
      Path idSyncFile;
      if (idSyncFileArg.isEmpty()) {
        // Create an empty temporary file used for coverage ID synchronization and
        // pass its path to the agent in every child process. This requires adding
        // the argument to argv for it to be picked up by libFuzzer, which then
        // forwards it to child processes.
        if (!IS_ANDROID) {
          idSyncFile = Files.createTempFile("jazzer-", "");
        } else {
          File f = File.createTempFile("jazzer-", "", new File("/data/local/tmp/"));
          idSyncFile = f.toPath();
        }

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

    if (args.stream().anyMatch("-merge_inner=1"::equals)) {
      Opt.mergeInner.setIfDefault(true);
    }

    // Jazzer's hooks use deterministic randomness and thus require a seed. Search for the last
    // occurrence of a "-seed" argument as that is the one that is used by libFuzzer. If none is
    // set, generate one and pass it to libFuzzer so that a fuzzing run can be reproduced simply by
    // setting the seed printed by libFuzzer.
    String seed =
        args.stream()
            .reduce(
                null,
                (prev, cur) -> cur.startsWith("-seed=") ? cur.substring("-seed=".length()) : prev);
    if (seed == null) {
      seed = Integer.toUnsignedString(new SecureRandom().nextInt());
      // Only add the -seed argument to the command line if not running in a mode
      // that spawns subprocesses. These would inherit the same seed, which might
      // make them less effective.
      if (!spawnsSubprocesses) {
        args.add("-seed=" + seed);
      }
    }
    System.setProperty("jazzer.internal.seed", seed);

    if (args.stream().noneMatch(arg -> arg.startsWith("-rss_limit_mb="))) {
      args.add(getDefaultRssLimitMbArg());
    }

    if (!Opt.instrumentOnly.get().isEmpty()) {
      if (Opt.dumpClassesDir.get().isEmpty()) {
        Log.error("--dump_classes_dir must be set with --instrument_only");
        exit(1);
      }
      boolean instrumentationSuccess = OfflineInstrumentor.instrumentJars(Opt.instrumentOnly.get());
      if (!instrumentationSuccess) {
        exit(1);
      }
      exit(0);
    }

    Driver.class.getClassLoader().setDefaultAssertionStatus(true);

    if (!Opt.autofuzz.get().isEmpty()) {
      AgentInstaller.install(Opt.hooks.get());
      FuzzTargetHolder.fuzzTarget = FuzzTargetHolder.AUTOFUZZ_FUZZ_TARGET;
      return FuzzTargetRunner.startLibFuzzer(args);
    }

    String targetClassName = FuzzTargetFinder.findFuzzTargetClassName();
    if (targetClassName == null) {
      Log.error("Missing argument --target_class=<fuzz_target_class>");
      exit(1);
    }

    // The JUnitRunner calls AgentInstaller.install itself after modifying flags affecting the
    // agent.
    if (JUnitRunner.isSupported()) {
      Optional<JUnitRunner> runner = JUnitRunner.create(targetClassName, args);
      if (runner.isPresent()) {
        return runner.get().run();
      }
    }

    // Installing the agent after the following "findFuzzTarget" leads to an asan error
    // in it on "Class.forName(targetClassName)", but only during native fuzzing.
    AgentInstaller.install(Opt.hooks.get());
    FuzzTargetHolder.fuzzTarget = FuzzTargetFinder.findFuzzTarget(targetClassName);
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
