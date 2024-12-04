#
# Copyright 2024 Code Intelligence GmbH
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
#

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
        expect_number_of_findings = 0,
        # By default, expect a crash iff allowed_findings isn't empty.
        expect_crash = None,
        expect_non_crash_exit_code = None,
        # If empty, expect no warnings or errors, if not empty, expect one matching the given regex.
        expected_warning_or_error = "",
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
            str(expect_non_crash_exit_code or -1),
            str(launcher_variant == "java"),
            str(expect_number_of_findings),
            "'" + expected_warning_or_error + "'",
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

_BASE_SEED = 2735196724

def fuzzer_benchmark(
        name,
        *,
        num_seeds,
        max_runs,
        env = {},
        fuzzer_args = [],
        tags = [],
        **kwargs):
    """Creates multiple instances of a Java fuzz target test with different seeds for benchmarking.

    The target `<name>` is a `test_suite` tagged with `"manual"`that can be used to run all
    individual instances of the fuzz target test at once. The individual tests are tagged with
    `"benchmark"` and `"manual"`. This is meant to run in CI and ensure that the maximum number of
    runs does not regress.

    The target `<name>.stats` can be run with `bazel run` to execute the benchmark and derive some
    statistics about the number of runs.

    This macro is set up specifically to make efficient use of Bazel's scheduling and caching
    capabilities: By having one target per run instead of a single target that runs the fuzz test
    multiple times, Bazel can schedule the runs concurrently and avoid timeouts on slow runners.
    When increasing the number of seeds, existing results can be reused from the cache.

    Args:
      num_seeds: The number of different seeds to try; corresponds to the number of individual tests
        generated.
      max_runs: The maximum number of runs that each individual test is allowed to run for. Keep
        this as low as possible with a small margin to catch regressions.
    """
    seed = _BASE_SEED
    tests = []
    for i in range(num_seeds):
        test_name = "{}_{}".format(name, i + 1)
        tests.append(test_name)
        java_fuzz_target_test(
            name = test_name,
            fuzzer_args = fuzzer_args + [
                "-print_final_stats=1",
                "-seed={}".format(seed),
                "-runs={}".format(max_runs),
            ],
            env = env | {"JAZZER_NO_EXPLICIT_SEED": "1"},
            tags = tags + ["manual", "benchmark"],
            verify_crash_input = False,
            verify_crash_reproducer = False,
            **kwargs
        )
        seed = (31 * seed) % 4294967295

    native.test_suite(
        name = name,
        tests = tests,
        tags = ["manual"],
    )

    native.sh_binary(
        name = name + ".stats",
        srcs = [Label("//bazel/tools:compute_benchmark_stats.sh")],
        env = {
            "TEST_SUITE_LABEL": str(native.package_relative_label(name)),
        },
        args = [
            native.package_name() + "/" + test
            for test in tests
        ],
    )

def all_tests_above():
    """Returns the labels of all test targets in the current package defined before this call."""
    return [
        ":" + r["name"]
        for r in native.existing_rules().values()
        if r["kind"].endswith("_test")
    ]
