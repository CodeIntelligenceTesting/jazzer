## Building Jazzer from source

### Dependencies

Jazzer has the following dependencies when being built from source:

* [Bazelisk](https://github.com/bazelbuild/bazelisk) or the version of Bazel specified in [`.bazelversion`](.bazelversion)
* One of the following C++ compilers:
  * [Clang](https://clang.llvm.org/) 9.0+ (clang-cl on Windows)
  * Xcode (Xcode.app is required, not just the developer tools)
  * GCC (should work with `--repo_env=CC=gcc`, but is not tested)

It is recommended to use [Bazelisk](https://github.com/bazelbuild/bazelisk) to automatically download and install Bazel.
Simply download the release binary for your OS and architecture and ensure that it is available in the `PATH`.
The instructions below will assume that this binary is called `bazel` - Bazelisk is a thin wrapper around the actual Bazel binary and can be used interchangeably.

### Building

Assuming the dependencies are installed, build Jazzer from source and run it as follows:

```bash
$ git clone https://github.com/CodeIntelligenceTesting/jazzer
$ cd jazzer
# Note the double dash used to pass <arguments> to Jazzer rather than Bazel.
$ bazel run //:jazzer -- <arguments>
```

You can also build your own version of the release binaries:

```bash
$ bazel build //:jazzer_release
...
INFO: Found 1 target...
Target //:jazzer_release up-to-date:
  bazel-bin/jazzer_release.tar.gz
...
```

#### Building for Android

Android builds are supported on Linux and macOS.
Local installations of an Android SDK and a corresponding side-by-side NDK are required.

Set the following environment variables:
* `ANDROID_HOME` points to the SDK root (e.g. `/home/user/Android/Sdk`)
* `ANDROID_NDK_HOME` points the NDK within the SDK (e.g. `/home/user/Android/Sdk/ndk/25.2.9519653`)

Then build Jazzer for Android via:

``` bash
$ bazel build //launcher/android:jazzer_android
```

### Running the tests

To run the tests, execute the following command:

```bash
$ bazel test //...
```

#### Debugging

If you need to debug an issue that can only be reproduced by an integration test (`java_fuzz_target_test`), you can start Jazzer in debug mode via `--config=debug`.
The JVM running Jazzer will suspend until a debugger connects on port 5005 (or the port specified via `DEFAULT_JVM_DEBUG_PORT`).

### Formatting

Run `./format.sh` to format all source files in the way enforced by the "Check formatting" CI job.

## Releasing (CI employees only)

1. Update `JAZZER_VERSION` in [`maven.bzl`](maven.bzl).
2. Trigger the "Prerelease" GitHub Actions workflow for the branch where you want to do the release:
    * `main` for major and minor releases
    * An appropriate release branch for patch releases
3. Wait for the workflow to finish (about 10 minutes)
4. When successful and happy with the results, log into https://oss.sonatype.org, select both staging repositories and "Close" them.
   Wait and refresh, then select them again and "Release" them.
5. Release the draft Github release. This will automatically create a tag, push the docker images and deploy the docs (can take about a few minutes to appear at [jazzer-docs]( https://codeintelligencetesting.github.io/jazzer-docs)).
