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

import com.google.devtools.build.runfiles.Runfiles;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FuzzTargetTestWrapper {
  public static void main(String[] args) {
    String driverActualPath;
    String jarActualPath;
    Runfiles runfiles;
    try {
      runfiles = Runfiles.create();
      driverActualPath = runfiles.rlocation(rlocationPath(args[0]));
      jarActualPath = runfiles.rlocation(rlocationPath(args[1]));
    } catch (IOException | ArrayIndexOutOfBoundsException e) {
      e.printStackTrace();
      System.exit(1);
      return;
    }

    ProcessBuilder processBuilder = new ProcessBuilder();
    Map<String, String> environment = processBuilder.environment();
    // Ensure that Jazzer can find its runfiles.
    environment.putAll(runfiles.getEnvVars());

    // Crashes will be available as test outputs. These are cleared on the next run,
    // so this is only useful for examples.
    String outputDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR");
    List<String> command =
        Stream
            .concat(Stream.of(driverActualPath, String.format("-artifact_prefix=%s/", outputDir),
                        String.format("--reproducer_path=%s", outputDir), "-seed=2735196724",
                        String.format("--cp=%s", jarActualPath)),
                Arrays.stream(args).skip(2))
            .collect(Collectors.toList());
    processBuilder.inheritIO();
    processBuilder.command(command);

    try {
      int exitCode = processBuilder.start().waitFor();
      // Assert that we either found a crash in Java (exit code 77) or a sanitizer crash (exit code
      // 76).
      if (exitCode != 76 && exitCode != 77) {
        System.exit(3);
      }
      String[] outputFiles = new File(outputDir).list();
      if (outputFiles == null) {
        System.exit(4);
      }
      // Verify that libFuzzer dumped a crashing input.
      if (Arrays.stream(outputFiles).noneMatch(name -> name.startsWith("crash-"))) {
        System.exit(5);
      }
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
      System.exit(2);
    }
    System.exit(0);
  }

  // Turns the result of Bazel's `$(rootpath ...)` into the correct format for rlocation.
  private static String rlocationPath(String rootpath) {
    if (rootpath.startsWith("external/")) {
      return rootpath.substring("external/".length());
    } else {
      return "jazzer/" + rootpath;
    }
  }
}
