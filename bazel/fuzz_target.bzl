# Copyright 2021 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def java_fuzz_target_test(
        name,
        target_class = None,
        target_method = None,
        deps = [],
        runtime_deps = [],
        hook_jar = None,
        data = [],
        launcher_variant = "java",
        tags = [],
        fuzzer_args = [],
        srcs = [],
        size = None,
        timeout = None,
        env = None,
        env_inherit = None,
        verify_crash_input = True,
        verify_crash_reproducer = True,
        # Superset of the findings the fuzzer is expected to find. Since fuzzing runs are not
        # deterministic across OSes, pinpointing the exact set of findings is difficult.
        allowed_findings = [],
        # By default, expect a crash iff allowed_findings isn't empty.
        expect_crash = None,
        **kwargs):
    if target_class:
        fuzzer_args = fuzzer_args + ["--target_class=" + target_class]
    if target_method:
        fuzzer_args = fuzzer_args + ["--target_method=" + target_method]
    if expect_crash == None:
        expect_crash = len(allowed_findings) != 0

    target_name = name + "_target"
    target_deploy_jar = target_name + "_deploy.jar"

    # Deps can only be specified on java_binary targets with sources, which
    # excludes e.g. Kotlin libraries wrapped into java_binary via runtime_deps.
    deps = deps + ["//deploy:jazzer-api"] if srcs else []
    native.java_binary(
        name = target_name,
        srcs = srcs,
        create_executable = False,
        visibility = ["//visibility:private"],
        deps = deps,
        runtime_deps = runtime_deps,
        testonly = True,
        tags = tags,
        **kwargs
    )

    if launcher_variant == "java":
        # With the Java driver, we expect fuzz targets to depend on Jazzer
        # rather than have the launcher start a JVM with Jazzer on the class
        # path.
        native.java_import(
            name = target_name + "_import",
            jars = [target_deploy_jar],
            testonly = True,
            tags = tags,
        )
        target_with_driver_name = target_name + "_driver"
        native.java_binary(
            name = target_with_driver_name,
            runtime_deps = [
                target_name + "_import",
                "//src/main/java/com/code_intelligence/jazzer:jazzer_import",
            ],
            main_class = "com.code_intelligence.jazzer.Jazzer",
            testonly = True,
            tags = tags,
        )

    if launcher_variant == "native":
        driver = "//launcher:jazzer"
    elif launcher_variant == "java":
        driver = target_with_driver_name
    else:
        fail("Invalid launcher variant: " + launcher_variant)

    native.java_test(
        name = name,
        runtime_deps = [
            "//bazel/tools/java:fuzz_target_test_wrapper",
        ],
        jvm_flags = [
            # Use the same memory settings for reproducers as those suggested by Jazzer when
            # encountering an OutOfMemoryError.
            "-Xmx1620m",
            # Ensure that reproducers can be compiled even if they contain UTF-8 characters.
            "-Dfile.encoding=UTF-8",
        ],
        size = size or "enormous",
        timeout = timeout or "moderate",
        # args are shell tokenized and thus quotes are required in the case where arguments
        # are empty.
        args = [
            "$(rlocationpath %s)" % driver,
            "$(rlocationpath //deploy:jazzer-api)",
            "$(rlocationpath %s)" % target_deploy_jar,
            "$(rlocationpath %s)" % hook_jar if hook_jar else "''",
            str(verify_crash_input),
            str(verify_crash_reproducer),
            str(expect_crash),
            str(launcher_variant == "java"),
            "'" + ",".join(allowed_findings) + "'",
        ] + fuzzer_args,
        data = [
            target_deploy_jar,
            "//deploy:jazzer-api",
            driver,
        ] + data + ([hook_jar] if hook_jar else []),
        env = env,
        env_inherit = env_inherit,
        main_class = "com.code_intelligence.jazzer.tools.FuzzTargetTestWrapper",
        use_testrunner = False,
        tags = tags,
    )
