/*
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

package com.code_intelligence.jazzer.sanitizers;

import java.io.IOException;
import static java.util.Collections.unmodifiableSet;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class OsCommandInjection {
    //Slightly safer command injection sanitizer that only allows 'java' to execute.
    //If necessary, this can be modified to allow an include list of allowed commands
    //as Jazzer does with ssrf, etc.
    public static String SENTINEL = "jazze";
    private static Set<String> ALLOWED_COMMANDS = Set.of("java");

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.lang.ProcessImpl",
            targetMethod = "start",
            // targetMethodDescriptor = "()Ljava/lang/Process;",
            additionalClassesToHook = {"java.lang.ProcessBuilder"}
    )
    public static void processImplStartHook (MethodHandle handle, Object thisObject,
                                                Object[] args, int hookId) throws IOException {
        String[] cmd_line_args = (String[])(args[0]);
        if (cmd_line_args == null || cmd_line_args.length == 0) {
            return;
        }
        String cmd = cmd_line_args[0];
        if (cmd == null || cmd.isEmpty()) {
            return;
        }
        String lcCmd = cmd.toLowerCase(Locale.US);
        if (lcCmd.contains("/") || lcCmd.contains("\\")) {
            Path cmdPath = Paths.get(cmd);
            lcCmd = cmdPath.getFileName().toString().toLowerCase(Locale.US);
        }
        if (lcCmd.equals(SENTINEL)) {
            Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical(String.format(
                    "OS Command Injection\nExecuting OS commands with attacker-controlled data can lead to remote code execution.")));
        }
        Jazzer.guideTowardsContainment(cmd, SENTINEL, hookId);
        if (ALLOWED_COMMANDS.contains(lcCmd)) {
            return;
        }
        throw new IOException("sorry, I'm not allowed to launch: " + cmd);
    }
}