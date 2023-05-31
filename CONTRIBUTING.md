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

Requires an account on [Sonatype](https://issues.sonatype.org) with access to the `com.code-intelligence` group as well as a YubiKey with the signing key.

### One-time setup

1. Install GPG prerequisites via `sudo apt-get install gnupg2 gnupg-agent scdaemon pcscd`.
2. Execute `mkdir -p ~/.gnupg && echo use-agent >> ~/.gnupg/gpg.conf` to enable GPG's smart card support.
3. Execute `cat deploy/maven.pub | gpg --import` to import the public key used for Maven signatures
4. Plug in the YubiKey and execute `gpg --card-status` to generate a key stub.
   If you see a `No such device` error, retry after executing `killall gpg-agent; killall pcscd` to remove existing locks on the YubiKey.

### Per release

1. Update `JAZZER_VERSION` in [`maven.bzl`](maven.bzl).
2. Create a release, using the auto-generated changelog as a base for the release notes.
3. Trigger the "Release" GitHub Actions workflow for the tag.
   This builds release archives for GitHub as well as the multi-architecture jar for the `com.code-intelligence:jazzer` Maven artifact.
4. Create a GitHub release and upload the contents of the `jazzer_releases` artifact from the workflow run.
5. Check out the tag locally and, with the YubiKey plugged in, run `bazel run //deploy` with the following environment variables to upload the Maven artifacts:
    * `JAZZER_JAR_PATH`: local path of the multi-architecture `jazzer.jar` contained in the `jazzer` artifact of the "Release" workflow
    * `MAVEN_USER`: username on https://oss.sonatype.org
    * `MAVEN_PASSWORD`: password on https://oss.sonatype.org

   The YubiKey blinks repeatedly and needs a touch to confirm each individual signature.
6. Log into https://oss.sonatype.org, select both staging repositories and "Close" them.
   Wait and refresh, then select them again and "Release" them.
7. Locally, with Docker credentials available, run `docker/push_all.sh` to build and push the `cifuzz/jazzer` and `cifuzz/jazzer-autofuzz` Docker images.

### Updating the hosted javadocs

Javadocs are hosted at https://codeintelligencetesting.github.io/jazzer-docs, which is populated from https://github.com/CodeIntelligenceTesting/jazzer-docs.

To update the docs after a release with API changes, follow these steps to get properly linked cross-references:

1. Delete the contents of the `jazzer-api` subdirectory of `jazzer-docs`.
2. Run `bazel build --//deploy:linked_javadoc //deploy:jazzer-api-docs` and unpack the jar into the `jazzer-api` subdirectory of `jazzer-docs`.
3. Commit and push the changes, then wait for them to be published (can take a minute).
4. Repeat the same steps with `jazzer-api` replaced by `jazzer` and then by `jazzer-junit`.
