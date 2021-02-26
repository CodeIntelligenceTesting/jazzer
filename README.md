<img src="https://www.code-intelligence.com/hubfs/Logos/CI%20Logos/Jazzer_einfach.png" height=150px alt="Jazzer logo">


# Jazzer
[![Maven Central](https://img.shields.io/maven-central/v/com.code-intelligence/jazzer-api)](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api)
![GitHub Actions](https://github.com/CodeIntelligenceTesting/jazzer/workflows/Build%20all%20targets%20and%20run%20all%20tests/badge.svg)

Jazzer is a coverage-guided, in-process fuzzer for the JVM platform developed by [Code Intelligence](https://code-intelligence.com).
It is based on [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and brings many of its instrumentation-powered mutation features to the JVM.

The JVM bytecode is executed inside the fuzzer process, which ensures fast execution speeds and allows seamless fuzzing of
native libraries.

## Installation

The preferred way to install Jazzer is to compile it from source using [Bazel](https://bazel.build), but binary distributions
are also available. At the moment Jazzer is only available for x64 Linux.

### Using Bazel

Jazzer has the following dependencies when being built from source:

* JDK 8 or later (e.g. [OpenJDK](https://openjdk.java.net/))
* [Clang](https://clang.llvm.org/) 9.0 or later (using a recent version is strongly recommended)

Jazzer uses [Bazelisk](https://github.com/bazelbuild/bazelisk) to automatically download and install Bazel. Building
Jazzer from source and running it thus only requires the following assuming the dependencies are installed:

```bash
git clone https://github.com/CodeIntelligenceTesting/jazzer
cd jazzer
# If Bazel is installed, use (note the double dash):
bazel run //:jazzer -- <arguments>
# If Bazel is not installed, use (note the double dash):
./bazelisk-linux-amd64 run //:jazzer -- <arguments>
```

### Using the provided binaries

Binary releases are available under [Releases](https://github.com/CodeIntelligenceTesting/jazzer/releases) and are built
using an [LLVM 11 Bazel toolchain](https://github.com/CodeIntelligenceTesting/llvm-toolchain).

The binary distributions of Jazzer consists of the following components:

- `jazzer_driver` - native binary that interfaces between libFuzzer and the JVM fuzz target
- `jazzer_agent_deploy.jar` - Java agent that performs bytecode instrumentation and tracks coverage
- `jazzer_api_deploy.jar` - contains convenience methods for creating fuzz targets and defining custom hooks
- `jazzer` - convenience shell script that runs the Jazzer driver with the local JRE shared libraries added to `LD_LIBRARY_PATH`

The additional release artifact `examples.jar` contains most of the examples and can be used to run them without having to build them (see Examples below).

After unpacking the archive, run Jazzer via

```bash
./jazzer <arguments>
```

If this leads to an error message saying that `libjvm.so` has not been found, the path to the local JRE needs to be
specified in the `JAVA_HOME` environment variable.

## Examples

Multiple examples for instructive and real-world Jazzer fuzz targets can be found in the `examples/` directory.
A toy example can be run as follows:

```bash
# Using Bazelisk:
./bazelisk-linux-amd64 run //examples:ExampleFuzzer
# Using the binary release and examples_deploy.jar:
./jazzer --cp=examples_deploy.jar
```

This should produce output similar to the following:

```
INFO: Loaded 1 hooks from com.example.ExampleFuzzerHooks
INFO: Instrumented com.example.ExampleFuzzer (took 81 ms, size +83%)
INFO: libFuzzer ignores flags that start with '--'
INFO: Seed: 2735196724
INFO: Loaded 1 modules   (65536 inline 8-bit counters): 65536 [0xe387b0, 0xe487b0),
INFO: Loaded 1 PC tables (65536 PCs): 65536 [0x7f9353eff010,0x7f9353fff010),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 2 ft: 2 corp: 1/1b exec/s: 0 rss: 94Mb
#1562   NEW    cov: 4 ft: 4 corp: 2/14b lim: 17 exec/s: 0 rss: 98Mb L: 13/13 MS: 5 ShuffleBytes-CrossOver-InsertRepeatedBytes-ShuffleBytes-CMP- DE: "magicstring4"-
#1759   REDUCE cov: 4 ft: 4 corp: 2/13b lim: 17 exec/s: 0 rss: 99Mb L: 12/12 MS: 2 ChangeBit-EraseBytes-
#4048   NEW    cov: 6 ft: 6 corp: 3/51b lim: 38 exec/s: 0 rss: 113Mb L: 38/38 MS: 4 ChangeBit-ChangeByte-CopyPart-CrossOver-
#4055   REDUCE cov: 6 ft: 6 corp: 3/49b lim: 38 exec/s: 0 rss: 113Mb L: 36/36 MS: 2 ShuffleBytes-EraseBytes-
#4266   REDUCE cov: 6 ft: 6 corp: 3/48b lim: 38 exec/s: 0 rss: 113Mb L: 35/35 MS: 1 EraseBytes-
#4498   REDUCE cov: 6 ft: 6 corp: 3/47b lim: 38 exec/s: 0 rss: 114Mb L: 34/34 MS: 2 EraseBytes-CopyPart-
#4764   REDUCE cov: 6 ft: 6 corp: 3/46b lim: 38 exec/s: 0 rss: 115Mb L: 33/33 MS: 1 EraseBytes-
#5481   REDUCE cov: 6 ft: 6 corp: 3/44b lim: 43 exec/s: 0 rss: 116Mb L: 31/31 MS: 2 InsertByte-EraseBytes-
#131072 pulse  cov: 6 ft: 6 corp: 3/44b lim: 1290 exec/s: 65536 rss: 358Mb

== Java Exception: java.lang.IllegalStateException: mustNeverBeCalled has been called
        at com.example.ExampleFuzzer.mustNeverBeCalled(ExampleFuzzer.java:38)
        at com.example.ExampleFuzzer.fuzzerTestOneInput(ExampleFuzzer.java:32)
DEDUP_TOKEN: eb6ee7d9b256590d
== libFuzzer crashing input ==
MS: 1 CMP- DE: "\x00C"-; base unit: 04e0ccacb50424e06e45f6184ad45895b6b8df8f
0x6d,0x61,0x67,0x69,0x63,0x73,0x74,0x72,0x69,0x6e,0x67,0x34,0x74,0x72,0x69,0x6e,0x67,0x34,0x74,0x69,0x67,0x34,0x7b,0x0,0x0,0x43,0x34,0xa,0x0,0x0,0x0,
magicstring4tring4tig4{\x00\x00C4\x0a\x00\x00\x00
artifact_prefix='./'; Test unit written to crash-efea1e8fc83a15217d512e20d964040a68a968c3
Base64: bWFnaWNzdHJpbmc0dHJpbmc0dGlnNHsAAEM0CgAAAA==
reproducer_path='.'; Java reproducer written to Crash_efea1e8fc83a15217d512e20d964040a68a968c3.java
```

Here you can see the usual libFuzzer output in case of a crash, augmented with JVM-specific information.
Instead of a native stack trace, the details of the uncaught Java exception that caused the crash are printed, followed by the fuzzer input that caused the exception to be thrown (if it is not too long).
More information on what hooks and Java reproducers are can be found below.

See `examples/BUILD.bazel` for the list of all possible example targets.

## Findings

Jazzer has so far uncovered the following vulnerabilities and bugs:

* [OWASP/json-sanitizer](https://github.com/OWASP/json-sanitizer) could be made to emit `</script>` and `]]>` in its output, which causes XSS ([CVE-2021-23899](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-23899), [fixed](https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0))
* [OWASP/json-sanitizer](https://github.com/OWASP/json-sanitizer) could be made to return invalid JSON or throw an undeclared exception ([CVE-2021-23900](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-23900), [fixed](https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0))
* [alibaba/fastjon](https://github.com/alibaba/fastjson) throws undeclared exceptions ([reported](https://github.com/alibaba/fastjson/issues/3631))
* [FasterXML/jackson-dataformats-binary](https://github.com/FasterXML/jackson-dataformats-binary) `CBORParser` throws an undeclared exception due to missing bounds checks when parsing Unicode ([fixed](https://github.com/FasterXML/jackson-dataformats-binary/issues/236))
* [FasterXML/jackson-dataformats-binary](https://github.com/FasterXML/jackson-dataformats-binary) `CBORParser` throws an undeclared exception on dangling arrays ([fixed](https://github.com/FasterXML/jackson-dataformats-binary/issues/240))
* [Apache/commons-imaging](https://commons.apache.org/proper/commons-imaging/) throws undeclared exceptions in parsers for multiple image formats (reported as [`IMAGING-275`](https://issues.apache.org/jira/browse/IMAGING-275) through [`IMAGING-279`](https://issues.apache.org/jira/browse/IMAGING-279))
* [netplex/json-smart-v1](https://github.com/netplex/json-smart-v1) and [netplex/json-smart-v2](https://github.com/netplex/json-smart-v2) throw an undeclared exception ([CVE-2021-27568](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27568), reported by @GanbaruTobi)

If you find bugs with Jazzer, we would be happy to hear from you!
Feel free to [open an issue](https://github.com/CodeIntelligenceTesting/jazzer/issues/new) or submit a pull request.

## Usage

### Creating a fuzz target

Jazzer requires a JVM class containing the entry point for the fuzzer. This is commonly referred to as a "fuzz target" and
may be as simple as the following Java example:

```java
package com.example.MyFirstFuzzTarget;

class MyFirstFuzzTarget {
    public static void fuzzerTestOneInput(byte[] input) {
        ...
        // Call the function under test with arguments derived from input and
        // throw an exception if something unwanted happens.
        ...
    }
}
```

A Java fuzz target class needs to define exactly one of the following functions:

* `public static void fuzzerTestOneInput(byte[] input)`: Ideal for fuzz targets that naturally work on raw byte input (e.g.
  image parsers).
* `public static void fuzzerTestOneInput(com.code_intelligence.api.FuzzedDataProvider data)`: A variety of types of "fuzzed
  data" is made available via the `FuzzedDataProvider` interface (see below for more information on this interface).

The fuzzer will repeatedly call this function with generated inputs. All unhandled exceptions are caught and
reported as errors.

The optional functions `public static void fuzzerInitialize()` or `public static void fuzzerInitialize(String[] args)`
can be defined if initial setup is required. These functions will be called once before
the first call to `fuzzerTestOneInput`.

The optional function `public static void fuzzerTearDown()` will be run just before the JVM is shut down.

### Running the fuzzer

The fuzz target needs to be compiled and packaged into a `.jar` archive. Assuming that this archive is called
`fuzz_target.jar` and depends on libraries available as `lib1.jar` and `lib2.jar`, fuzzing is started by
invoking Jazzer with the following arguments:

```bash
--cp=fuzz_target.jar:lib1.jar:lib2.jar --target_class=com.example.MyFirstFuzzTarget <optional_corpus_dir>
```

The fuzz target class can optionally be specified by adding it as the value of the `Jazzer-Fuzz-Target-Class` attribute
in the JAR's manifest. If there is only a single such attribute among all manifests of JARs on the classpath, Jazzer will
use its value as the fuzz target class.

Bazel produces the correct type of `.jar` from a `java_binary` target with `create_executable = False` and
`deploy_manifest_lines = ["Jazzer-Fuzz-Target-Class: com.example.MyFirstFuzzTarget"]` by adding the suffix `_deploy.jar`
to the target name.

### Fuzzed Data Provider

For most non-trivial fuzz targets it is necessary to further process the byte array passed from the fuzzer, for example
to extract multiple values or convert the input into a valid `java.lang.String`. We provide functionality similar to
[atheris'](https://github.com/google/atheris) `FuzzedDataProvider` and libFuzzer's `FuzzedDataProvider.h` to simplify
the task of writing JVM fuzz targets.

If the function `public static void fuzzerTestOneInput(FuzzedDataProvider data)` is defined in the fuzz target, it will
be passed an object implementing `com.code_intelligence.jazzer.api.FuzzedDataProvider` that allows _consuming_ the raw fuzzer
input as values of common types. This can look as follows:

```java
package com.example.MySecondFuzzTarget;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class MySecondFuzzTarget {
    public satic void callApi(int val, String text) {
        ...
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        callApi1(data.consumeInt(), data.consumeRemainingAsString());
        return false;
    }
}
```

The `FuzzedDataProvider` interface definition is contained in `jazzer_api_deploy.jar` in the binary release and can be
built by the Bazel target `//agent:jazzer_api_deploy.jar`. It is also available from
[Maven Central](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).
For additional information, see the
[javadocs](https://codeintelligencetesting.github.io/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html).

It is highly recommended to use `FuzzedDataProvider` for generating `java.lang.String` objects inside the fuzz target
instead of converting the raw byte array to directly via a `String` constructor as the `FuzzedDataProvider` implementation is
engineered to minimize copying and generate both valid and invalid ASCII-only and Unicode strings.

### Reproducing a bug

When Jazzer manages to find an input that causes an uncaught exception or a failed assertion, it prints a Java
stack trace and creates two files that aid in reproducing the crash without Jazzer:

* `crash-<sha1_of_input>` contains the raw bytes passed to the fuzz target (just as with libFuzzer C/C++ fuzz targets).
  The crash can be reproduced with Jazzer by passing the path to the crash file as the only positional argument.
* `Crash-<sha1_of_input>.java` contains a class with a `main` function that invokes the fuzz target with the
  crashing input. This is especially useful if using `FuzzedDataProvider` as the raw bytes of the input do not
  directly correspond to the values consumed by the fuzz target. The `.java` file can be compiled with just
  the fuzz target and its dependencies in the classpath (plus `jazzer_api_deploy.jar` if using `FuzzedDataProvider).

### Minimizing a crashing input

Every crash stack trace is accompanied by a `DEDUP_TOKEN` that uniquely identifies the relevant parts of the stack
trace. This value is used by libFuzzer while minimizing a crashing input to ensure that the smaller inputs reproduce
the "same" bug. To minimize a crashing input, execute Jazzer with the following arguments in addition to `--cp` and
`--target_class`:

```bash
-minimize_crash=1 <path/to/crashing_input>
```

### Parallel execution

libFuzzer offers the `-fork=N` and `-jobs=N` flags for parallel fuzzing, both of which are also supported by Jazzer.

### Limitations

Jazzer currently maintains coverage information in a global variable that is shared among threads. This means that while
fuzzing multi-threaded fuzz targets is theoretically possible, the reported coverage information may be misleading.

## Advanced Options

Various command line options are available to control the instrumentation and fuzzer execution. Since Jazzer is a
libFuzzer-compiled binary, all positional and single dash command-line options are parsed by libFuzzer. Therefore, all
Jazzer options are passed via double dash command-line flags, i.e., as `--option=value` (note the `=` instead of a space).

A full list of command-line flags can be printed with the `--help` flag. For the available libFuzzer options please refer
to [its documentation](https://llvm.org/docs/LibFuzzer.html) for a detailed description.

### Coverage Instrumentation

The Jazzer agent inserts coverage markers into the JVM bytecode during class loading. libFuzzer uses this information
to guide its input mutations towards increased coverage.

It is possible to restrict instrumentation to only a subset of classes with the `--instrumentation_includes` flag. This
is especially useful if coverage inside specific packages is of higher interest, e.g., the user library under test rather than an
external parsing library in which the fuzzer is likely to get lost. Similarly, there is `--instrumentation_excludes` to
exclude specific classes from instrumentation. Both flags take a list of glob patterns for the java class name separated
by colon:

```bash
--instrumentation_includes=com.my_com.**:com.other_com.** --instrumentation_excludes=com.my_com.crypto.**
```

By default, JVM-internal classes and Java as well as Kotlin standard library classes are not instrumented, so these do not
need to be excluded manually.

### Trace Instrumentation

The agent adds additional hooks for tracing compares, integer divisions, switch statements and array indices.
These hooks correspond to [clang's data flow hooks](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow).
The particular instrumentation types to apply can be specified using the `--trace` flag, which accepts the following values:

* `cov`: AFL-style edge coverage
* `cmp`: compares (int, long, String) and switch cases
* `div`: divisors in integer divisions
* `gep`: constant array indexes
* `all`: shorthand to apply all available instrumentations

Multiple instrumentation types can be combined with a colon.

### Value Profile

The run-time flag `-use_value_profile=1` enables [libFuzzer's value profiling mode](https://llvm.org/docs/LibFuzzer.html#value-profile).
When running with this flag, the feedback about compares and constants received from Jazzer's trace instrumentation is
associated with the particular bytecode location and used to provide additional coverage instrumentation.
See [ExampleValueProfileFuzzer.java](https://github.com/CodeIntelligenceTesting/jazzer/tree/main/examples/src/main/java/com/example/ExampleValueProfileFuzzer.java)
for a fuzz target that would be very hard to fuzz without value profile.

As passing the bytecode location back to libFuzzer requires inline assembly and may thus not be fully portable, it can be disabled
via the flag `--nofake_pcs`.

### Custom Hooks

In order to obtain information about data passed into functions such as `String.equals` or `String.startsWith`, Jazzer
hooks invocations to these methods. This functionality is also available to fuzz targets, where it can be used to implement
custom sanitizers or stub out methods that block the fuzzer from progressing (e.g. checksum verifications or random number generation).
See [ExampleFuzzerHooks.java](https://github.com/CodeIntelligenceTesting/jazzer/tree/main/examples/src/main/java/com/example/ExampleFuzzerHooks.java)
for an example of such a hook.

Method hooks can be declared using the `@MethodHook` annotation defined in the `com.code_intelligence.jazzer.api` package,
which is contained in `jazzer_api_deploy.jar` (binary release) or built by the target `//agent:jazzer_api_deploy.jar` (Bazel).
It is also available from
[Maven Central](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).
See the [javadocs of the `@MethodHook` API](https://codeintelligencetesting.github.io/jazzer-api/com/code_intelligence/jazzer/api/MethodHook.html)
for more details.

To use the compiled method hooks they have to be available on the classpath provided by `--cp` and can then be loaded by providing the
flag `--custom_hooks`, which takes a colon-separated list of names of classes to load hooks from.
This list of custom hooks can alternatively be specified via the `Jazzer-Hook-Classes` attribute in the fuzz target
JAR's manifest.

### Suppressing stack traces

With the flag `--keep_going=N` Jazzer continues fuzzing until `N` unique stack traces have been encountered.

Particular stack traces can also be ignored based on their `DEDUP_TOKEN` by passing a comma-separated list of tokens
via `--ignore=<token_1>,<token2>`.

## Advanced fuzzed targets

### Fuzzing with Native Libraries

Jazzer supports fuzzing of native libraries loaded by the JVM, for example via `System.load()`. For the fuzzer to get
coverage feedback, these libraries have to be compiled with `-fsanitize=fuzzer-no-link`.

Additional sanitizers such as AddressSanitizer are often desirable to uncover bugs inside the native libraries. This
requires compiling the library with `-fsanitize=fuzzer-no-link,address` and using the asan-ified driver available
as the Bazel target `//:jazzer_asan`.

**Note:** Sanitizers other than AddressSanitizer are not yet supported. Furthermore, due to the nature of the JVM's GC,
LeakSanitizer reports currently too many false positives to be useful and are thus disabled.

The fuzz target `ExampleFuzzerWithNative` in the `examples/` directory contains a minimal working example for fuzzing
with native libraries. Also see `TurboJpegFuzzer` for a real-world example.

### Fuzzing with Custom Mutators

LibFuzzer API offers two functions to customize the mutation strategy which is especially useful when fuzzing functions
that require structured input. Jazzer does not define `LLVMFuzzerCustomMutator` nor `LLVMFuzzerCustomCrossOver` and
leaves the mutation strategy entirely to libFuzzer. However, custom mutators can easily be integrated by
compiling a mutator library which defines `LLVMFuzzerCustomMutator` (and optionally `LLVMFuzzerCustomCrossOver`) and
pre-loading the mutator library:

```bash
# Using Bazel:
LD_PRELOAD=libcustom_mutator.so ./bazelisk-linux-amd64 run //:jazzer -- <arguments>
# Using the binary release:
LD_PRELOAD=libcustom_mutator.so ./jazzer <arguments>
```

## Credit

The following developers have contributed to Jazzer:

[Sergej Dechand](https://github.com/serj),
[Christian Hartlage](https://github.com/dende),
[Fabian Meumertzheim](https://github.com/fmeum),
[Sebastian Pöplau](https://github.com/sebastianpoeplau),
[Mohammed Qasem](https://github.com/mohqas),
[Simon Resch](https://github.com/simonresch),
[Henrik Schnor](https://github.com/henrikschnor),
[Khaled Yakdan](https://github.com/kyakdan)

The LLVM-style edge coverage instrumentation for JVM bytecode used by Jazzer relies on [JaCoCo](https://github.com/jacoco/jacoco).
Previously, Jazzer used AFL-style coverage instrumentation as pioneered by [kelinci](https://github.com/isstac/kelinci).

<p align="center">
<a href="https://www.code-intelligence.com"><img src="https://www.code-intelligence.com/hubfs/Logos/CI%20Logos/CI_Header_GitHub_quer.jpeg" height=50px alt="Code Intelligence logo"></a>
</p>
