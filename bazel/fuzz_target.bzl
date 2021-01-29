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
        target_class,
        hook_classes = [],
        native_libs = [],
        use_asan = False,
        visibility = None,
        tags = [],
        fuzzer_args = [],
        **kwargs):
    target_name = name + "_target"
    native.java_binary(
        name = target_name,
        visibility = ["//visibility:private"],
        create_executable = False,
        **kwargs
    )

    additional_args = []

    hooks = ":".join(hook_classes)
    if hooks != "":
        additional_args.append("--custom_hooks=" + hooks)

    native_libs_paths = ":".join(["$$(dirname $(rootpaths %s) | paste -sd ':' -)" % native_lib for native_lib in native_libs])
    if native_libs_paths != "":
        additional_args.append("--jvm_args=-Djava.library.path=" + native_libs_paths)

    driver = "//driver:jazzer_driver_asan" if use_asan else "//driver:jazzer_driver"

    native.sh_test(
        name = name,
        srcs = ["//bazel:fuzz_target_test_wrapper.sh"],
        size = "large",
        timeout = "moderate",
        args = [
            "$(rootpath %s)" % driver,
            "--cp=$(rootpath :%s_deploy.jar)" % target_name,
            "--target_class=" + target_class,
            "--agent_path=$(rootpath //agent:jazzer_agent_deploy.jar)",
            # Should be bigger than the JVM max heap size (4096m)
            "-rss_limit_mb=5000",
        ] + additional_args + fuzzer_args,
        data = [
            ":%s_deploy.jar" % target_name,
            "//agent:jazzer_agent_deploy.jar",
            driver,
        ] + native_libs,
        tags = tags,
        visibility = visibility,
    )
