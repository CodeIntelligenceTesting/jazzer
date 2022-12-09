## Building Jazzer from source

### Dependencies

Jazzer has the following dependencies when being built from source:

* [Bazelisk](https://github.com/bazelbuild/bazelisk) or the version of Bazel specified in [`.bazelversion`](.bazelversion)
* JDK 8 to 19 (e.g. [OpenJDK](https://openjdk.java.net/))
* [Clang](https://clang.llvm.org/) 9.0 or later (using GCC should work with `--repo_env=CC=gcc`, but is not tested)

It is recommended to use [Bazelisk](https://github.com/bazelbuild/bazelisk) to automatically download and install Bazel.
Simply download the release binary for your OS and architecture and ensure that it is available in the `PATH`.
The instructions below will assume that this binary is called `bazel` - Bazelisk is a thin wrapper around the actual Bazel binary and can be used interchangeably.

### Compiling

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

#### macOS

The build may fail with the clang shipped with Xcode.
In that case, install LLVM clang via `brew install llvm` and set `CC` to the path of LLVM clang.

#### Windows

`clang-cl` is required to build Jazzer on Windows.

### Running the tests

To run the tests, execute the following command:

```bash
$ bazel test //...
```

### Formatting

Run `./format.sh` to format all source files in the way enforced by the "Check formatting" CI job.
See [check-formatting.yml](.github/workflows/check-formatting.yml) for how to obtain the particular versions of the required formatting tools.

## Releasing (CI employees only)

Requires an accounts on [Sonatype](https://issues.sonatype.org) with access to the `com.code-intelligence` group as well as a YubiKey with the signing key.

1. Update `JAZZER_VERSION` in [`maven.bzl`](maven.bzl).
2. Create a tag for the release.
3. Push the tag to the private fork at https://github.com/CodeIntelligenceTesting/jazzer-trusted.
4. Trigger the "Release" GitHub Actions workflow for the tag **in `jazzer-trusted`**.
   This builds release archives for GitHub as well as the multi-architecture jar for the `com.code-intelligence:jazzer` Maven artifact.
   Using `jazzer-trusted` is unfortunately required as there is [no safe way to add a private runner to a public repository](https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#self-hosted-runner-security) and there are no public macOS M1 runners.
5. Create a GitHub release and upload the contents of the `jazzer_releases` artifact from the workflow run.
6. Check out the tag locally and, with the YubiKey plugged in, run `bazel run //deploy` with the following environment variables to upload the Maven artifacts:
    * `JAZZER_JAR_PATH`: local path of the multi-architecture `jazzer.jar` contained in the `jazzer` artifact of the "Release" workflow
    * `JAVA_HOME`: path to a JDK 8
    * `MAVEN_USER`: username on https://oss.sonatype.org
    * `MAVEN_PASSWORD`: password on https://oss.sonatype.org

   The YubiKey blinks repeatedly and needs a touch to confirm each individual signature.
7. Log into https://oss.sonatype.org, select both staging repositories and "Close" them.
   Wait and refresh, then select them again and "Release" them.
8. Locally, with Docker credentials available, run `docker/push_all.sh` to build and push the `cifuzz/jazzer` and `cifuzz/jazzer-autofuzz` Docker images.

### Updating the hosted javadocs

Javadocs are hosted at https://codeintelligencetesting.github.io/jazzer-docs, which is populated from https://github.com/CodeIntelligenceTesting/jazzer-docs.

To update the docs after a release with API changes, follow these steps to get properly linked cross-references:

1. Delete the contents of all subdirectories of `jazzer-docs`.
2. Run `bazel build --//deploy:linked_javadoc //deploy:jazzer-api-docs` and unpack the jar into the `jazzer-api` subdirectory of `jazzer-docs`.
3. Commit and push the changes, then wait for them to be published (can take a minute).
4. Run `bazel build --//deploy:linked_javadoc //deploy:jazzer-docs` and unpack the jar into the `jazzer` subdirectory of `jazzer-docs`.
5. Commit and push the changes, then wait for them to be published (can take a minute).
6. Run `bazel build --//deploy:linked_javadoc //deploy:jazzer-junit-docs` and unpack the jar into the `jazzer-junit` subdirectory of `jazzer-docs`.
7. Commit and push the changes, then wait for them to be published (can take a minute).
