<img src="https://www.code-intelligence.com/hubfs/Logos/CI%20Logos/Jazzer_einfach.png" height=150px alt="Jazzer logo">


# Jazzer
[![Maven Central](https://img.shields.io/maven-central/v/com.code-intelligence/jazzer-api)](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api)
![GitHub Actions](https://github.com/CodeIntelligenceTesting/jazzer/workflows/Build%20all%20targets%20and%20run%20all%20tests/badge.svg)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/java-example.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:java-example)

Jazzer is a coverage-guided, in-process fuzzer for the JVM platform developed by [Code Intelligence](https://code-intelligence.com).
It is based on [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and brings many of its instrumentation-powered mutation features to the JVM.

The JVM bytecode is executed inside the fuzzer process, which ensures fast execution speeds and allows seamless fuzzing of
native libraries.

Jazzer currently supports the following platforms:
* Linux x86_64
* macOS 10.15+ x86_64 (experimental support for arm64)
* Windows x86_64

## News: Jazzer available in OSS-Fuzz

[Code Intelligence](https://code-intelligence.com) and Google have teamed up to bring support for Java, Kotlin, and other JVM-based languages to [OSS-Fuzz](https://github.com/google/oss-fuzz), Google's project for large-scale fuzzing of open-souce software. Read [the blogpost](https://security.googleblog.com/2021/03/fuzzing-java-in-oss-fuzz.html) over at the Google Security Blog.

If you want to learn more about Jazzer and OSS-Fuzz, [watch the FuzzCon 2020 talk](https://www.youtube.com/watch?v=SmH3Ys_k8vA&list=PLI0R_0_8-TV55gJU-UXrOzZoPbVOj1CW6&index=3) by [Abhishek Arya](https://twitter.com/infernosec) and [Fabian Meumertzheim](https://twitter.com/fhenneke).

## Getting Jazzer

### Using Docker

The "distroless" Docker image [cifuzz/jazzer](https://hub.docker.com/r/cifuzz/jazzer) includes Jazzer together with OpenJDK 11. Just mount a directory containing your compiled fuzz target into the container under `/fuzzing` by running:

```sh
docker run -v path/containing/the/application:/fuzzing cifuzz/jazzer <arguments>
```

If Jazzer produces a finding, the input that triggered it will be available in the same directory.

### Compiling with Bazel

#### Dependencies

Jazzer has the following dependencies when being built from source:

* Bazel 4 or later
* JDK 8 or later (e.g. [OpenJDK](https://openjdk.java.net/))
* [Clang](https://clang.llvm.org/) and [LLD](https://lld.llvm.org/) 9.0 or later (using a recent version is strongly recommended)

It is recommended to use [Bazelisk](https://github.com/bazelbuild/bazelisk) to automatically download and install Bazel.
Simply download the release binary for your OS and architecture and ensure that it is available in the `PATH`.
The instructions below will assume that this binary is called `bazel` - Bazelisk is a thin wrapper around the actual Bazel binary and can be used interchangeably.

#### Compilation

Assuming the dependencies are installed, build Jazzer from source as follows:

```bash
$ git clone https://github.com/CodeIntelligenceTesting/jazzer
$ cd jazzer
# Note the double dash used to pass <arguments> to Jazzer rather than Bazel.
$ bazel run //:jazzer -- <arguments>
```

If you prefer to build binaries that can be run without Bazel, use the following command to build your own archive with release binaries:

```bash
$ bazel build //:jazzer_release
...
INFO: Found 1 target...
Target //:jazzer_release up-to-date:
  bazel-bin/jazzer_release.tar.gz
...
```

This will print the path of a `jazzer_release.tar.gz` archive that contains the same binaries that would be part of a release.

##### macOS

The build may fail with the clang shipped with Xcode. If you encounter issues during the build, add `--config=toolchain`
right after `run` or `build` in the `bazelisk` commands above to use a checked-in toolchain that is known to work.
Alternatively, manually install LLVM and set `CC` to the path of LLVM clang.

#### rules_fuzzing

Support for Jazzer has recently been added to [rules_fuzzing](https://github.com/bazelbuild/rules_fuzzing), the official Bazel rules for fuzzing.
See their README for instructions on how to use Jazzer in a Java Bazel project.

### Using the provided binaries

Binary releases are available under [Releases](https://github.com/CodeIntelligenceTesting/jazzer/releases),
but do not always include the latest changes.

The binary distributions of Jazzer consist of the following components:

- `jazzer` - main binary
- `jazzer_agent_deploy.jar` - Java agent that performs bytecode instrumentation and tracks coverage (automatically loaded by `jazzer`)
- `jazzer_api_deploy.jar` - contains convenience methods for creating fuzz targets and defining custom hooks

The additional release artifact `examples_deploy.jar` contains most of the examples and can be used to run them without having to build them (see Examples below).

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
# Using Bazel:
bazel run //examples:ExampleFuzzer
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

## Usage

### Creating a fuzz target

Jazzer requires a JVM class containing the entry point for the fuzzer. This is commonly referred to as a "fuzz target" and
may be as simple as the following Java example:

```java
package com.example.MyFirstFuzzTarget;

public class MyFirstFuzzTarget {
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

#### Kotlin

An example of a Kotlin fuzz target can be found in
[KlaxonFuzzer.kt](https://github.com/CodeIntelligenceTesting/jazzer/tree/main/examples/src/main/java/com/example/KlaxonFuzzer.kt).

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

public class MySecondFuzzTarget {
    public static void callApi(int val, String text) {
        ...
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        callApi1(data.consumeInt(), data.consumeRemainingAsString());
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

### Autofuzz mode

The Autofuzz mode enables fuzzing arbitrary methods without having to manually create fuzz targets.
Instead, Jazzer will attempt to generate suitable and varied inputs to a specified methods using only public API functions available on the classpath.

To use Autofuzz, specify the `--autofuzz` flag and provide a fully [qualified method reference](https://docs.oracle.com/javase/specs/jls/se8/html/jls-15.html#jls-15.13), e.g.:
```
--autofuzz=org.apache.commons.imaging.Imaging::getBufferedImage
```
To autofuzz a constructor the `ClassType::new` format can be used.  
If there are multiple overloads, and you want Jazzer to only fuzz one, you can optionally specify the signature of the method to fuzz:
```
--autofuzz=org.apache.commons.imaging.Imaging::getBufferedImage(java.io.InputStream,java.util.Map)
```
The format of the signature agrees with that obtained from the part after the `#` of the link to the Javadocs for the particular method.

Under the hood, Jazzer tries various ways of creating objects from the fuzzer input. For example, if a parameter is an
interface or an abstract class, it will look for all concrete implementing classes on the classpath.
Jazzer can also create objects from classes that follow the [builder design pattern](https://www.baeldung.com/creational-design-patterns#builder)
or have a default constructor and use setters to set the fields.

Creating objects from fuzzer input can lead to many reported exceptions.
Jazzer addresses this issue by ignoring exceptions that the target method declares to throw.
In addition to that, you can provide a list of exceptions to be ignored during fuzzing via the `--autofuzz_ignore` flag in the form of a comma-separated list.
You can specify concrete exceptions (e.g., `java.lang.NullPointerException`), in which case also subclasses of these exception classes will be ignored, or glob patterns to ignore all exceptions in a specific package (e.g. `java.lang.*` or `com.company.**`).

When fuzzing with `--autofuzz`, Jazzer automatically enables the `--keep_going` mode to keep fuzzing indefinitely after the first finding.
Set `--keep_going=N` explicitly to stop after the `N`-th finding.

#### Docker
To facilitate using the Autofuzz mode, there is a docker image that you can use to fuzz libraries just by providing their Maven coordinates.
The dependencies will then be downloaded and autofuzzed:

```sh
docker run cifuzz/jazzer-autofuzz <Maven coordinates> --autofuzz=<method reference> <further arguments>
```

As an example, you can autofuzz the `json-sanitizer` library as follows:
```sh
docker run -it cifuzz/jazzer-autofuzz \
   com.mikesamuel:json-sanitizer:1.2.0 \
   com.google.json.JsonSanitizer::sanitize \
   --autofuzz_ignore=java.lang.ArrayIndexOutOfBoundsException \
   --keep_going=1
```

####

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

## Findings

Jazzer has so far uncovered the following vulnerabilities and bugs:

| Project | Bug      | Status | CVE | found by |
| ------- | -------- | ------ | --- | -------- |
| [OpenJDK](https://github.com/openjdk/jdk) | `OutOfMemoryError` via a small BMP image | [fixed](https://openjdk.java.net/groups/vulnerability/advisories/2022-01-18) | [CVE-2022-21360](https://nvd.nist.gov/vuln/detail/CVE-2022-21360) | [Code Intelligence](https://code-intelligence.com) |
| [OpenJDK](https://github.com/openjdk/jdk) | `OutOfMemoryError` via a small TIFF image | [fixed](https://openjdk.java.net/groups/vulnerability/advisories/2022-01-18) | [CVE-2022-21366](https://nvd.nist.gov/vuln/detail/CVE-2022-21366) | [Code Intelligence](https://code-intelligence.com) |
| [protocolbuffers/protobuf](https://github.com/protocolbuffers/protobuf) | Small protobuf messages can consume minutes of CPU time | [fixed](https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-wrvw-hg22-4m67) | [CVE-2021-22569](https://nvd.nist.gov/vuln/detail/CVE-2021-22569) | [OSS-Fuzz](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=39330) |
| [jhy/jsoup](https://github.com/jhy/jsoup) | More than 19 Bugs found in HTML and XML parser | [fixed](https://github.com/jhy/jsoup/security/advisories/GHSA-m72m-mhq2-9p6c) | [CVE-2021-37714](https://nvd.nist.gov/vuln/detail/CVE-2021-37714) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | Infinite loop when loading a crafted 7z | fixed | [CVE-2021-35515](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35515) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | `OutOfMemoryError` when loading a crafted 7z | fixed | [CVE-2021-35516](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35516) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | Infinite loop when loading a crafted TAR | fixed | [CVE-2021-35517](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35517) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | `OutOfMemoryError` when loading a crafted ZIP | fixed | [CVE-2021-36090](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36090) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/PDFBox](https://pdfbox.apache.org/) | Infinite loop when loading a crafted PDF | fixed | [CVE-2021-27807](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-27807) | [Code Intelligence](https://code-intelligence.com) |
| [Apache/PDFBox](https://pdfbox.apache.org/) | OutOfMemoryError when loading a crafted PDF | fixed | [CVE-2021-27906](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-27906) | [Code Intelligence](https://code-intelligence.com) |
| [netplex/json-smart-v1](https://github.com/netplex/json-smart-v1) <br/> [netplex/json-smart-v2](https://github.com/netplex/json-smart-v2) | `JSONParser#parse` throws an undeclared exception | [fixed](https://github.com/netplex/json-smart-v2/issues/60) | [CVE-2021-27568](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27568) | [@GanbaruTobi](https://github.com/GanbaruTobi) |
| [OWASP/json-sanitizer](https://github.com/OWASP/json-sanitizer) | Output can contain`</script>` and `]]>`, which allows XSS | [fixed](https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0) | [CVE-2021-23899](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-23899) | [Code Intelligence](https://code-intelligence.com) |
| [OWASP/json-sanitizer](https://github.com/OWASP/json-sanitizer) | Output can be invalid JSON and undeclared exceptions can be thrown | [fixed](https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0) | [CVE-2021-23900](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-23900) | [Code Intelligence](https://code-intelligence.com) |
| [alibaba/fastjon](https://github.com/alibaba/fastjson) | `JSON#parse` throws undeclared exceptions | [fixed](https://github.com/alibaba/fastjson/issues/3631) | | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | Infinite loop and `OutOfMemoryError` in `TarFile` | [fixed](https://issues.apache.org/jira/browse/COMPRESS-569) | | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-compress](https://commons.apache.org/proper/commons-compress/) | `NullPointerException` in `ZipFile`| [fixed](https://issues.apache.org/jira/browse/COMPRESS-568) | | [Code Intelligence](https://code-intelligence.com) |
| [Apache/commons-imaging](https://commons.apache.org/proper/commons-imaging/) | Parsers for multiple image formats throw undeclared exceptions | [reported](https://issues.apache.org/jira/browse/IMAGING-279?jql=project%20%3D%20%22Commons%20Imaging%22%20AND%20reporter%20%3D%20Meumertzheim%20) | | [Code Intelligence](https://code-intelligence.com) |
| [Apache/PDFBox](https://pdfbox.apache.org/) | Various undeclared exceptions | [fixed](https://issues.apache.org/jira/browse/PDFBOX-5108?jql=project%20%3D%20PDFBOX%20AND%20reporter%20in%20(Meumertzheim)) | | [Code Intelligence](https://code-intelligence.com) |
| [cbeust/klaxon](https://github.com/cbeust/klaxon) | Default parser throws runtime exceptions | [fixed](https://github.com/cbeust/klaxon/pull/330) | | [Code Intelligence](https://code-intelligence.com) |
| [FasterXML/jackson-dataformats-binary](https://github.com/FasterXML/jackson-dataformats-binary) | `CBORParser` throws an undeclared exception due to missing bounds checks when parsing Unicode | [fixed](https://github.com/FasterXML/jackson-dataformats-binary/issues/236) | | [Code Intelligence](https://code-intelligence.com) |
| [FasterXML/jackson-dataformats-binary](https://github.com/FasterXML/jackson-dataformats-binary) | `CBORParser` throws an undeclared exception on dangling arrays | [fixed](https://github.com/FasterXML/jackson-dataformats-binary/issues/240) | | [Code Intelligence](https://code-intelligence.com) |
| [ngageoint/tiff-java](https://github.com/ngageoint/tiff-java) | `readTiff ` Index Out Of Bounds | [fixed](https://github.com/ngageoint/tiff-java/issues/38) | | [@raminfp](https://github.com/raminfp) |
| [google/re2j](https://github.com/google/re2j) | `NullPointerException` in `Pattern.compile` | [reported](https://github.com/google/re2j/issues/148) | | [@schirrmacher](https://github.com/schirrmacher) |
| [google/gson](https://github.com/google/gson) | `ArrayIndexOutOfBounds` in `ParseString` | [fixed](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=40838) | | [@DavidKorczynski](https://twitter.com/Davkorcz) |

As Jazzer is used to fuzz JVM projects in OSS-Fuzz, an additional list of bugs can be found [on the OSS-Fuzz issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3A%22json-sanitizer%22%20OR%20proj%3A%22fastjson2%22%20OR%20proj%3A%22jackson-core%22%20OR%20proj%3A%22jackson-dataformats-binary%22%20OR%20proj%3A%22jackson-dataformats-xml%22%20OR%20proj%3A%22apache-commons%22%20OR%20proj%3A%22jsoup%22&can=1).

If you find bugs with Jazzer, we would like to hear from you!
Feel free to [open an issue](https://github.com/CodeIntelligenceTesting/jazzer/issues/new) or submit a pull request.

## Advanced Options

Various command line options are available to control the instrumentation and fuzzer execution. Since Jazzer is a
libFuzzer-compiled binary, all positional and single dash command-line options are parsed by libFuzzer. Therefore, all
Jazzer options are passed via double dash command-line flags, i.e., as `--option=value` (note the `=` instead of a space).

A full list of command-line flags can be printed with the `--help` flag. For the available libFuzzer options please refer
to [its documentation](https://llvm.org/docs/LibFuzzer.html) for a detailed description.

### Passing JVM arguments

When Jazzer is launched, it starts a JVM in which it executes the fuzz target.
Arguments for this JVM can be provided via the `JAVA_OPTS` environment variable.

Alternatively, arguments can also be supplied via the `--jvm_args` argument.
Multiple arguments are delimited by the classpath separator, which is `;` on Windows and `:` else.
For example, to enable preview features as well as set a maximum heap size, add the following to the Jazzer invocation:

```bash
# Windows
--jvm_args=--enable-preview;-Xmx1000m
# Linux & macOS
--jvm_args=--enable-preview:-Xmx1000m
```

Arguments specified with `--jvm_args` take precendence over those in `JAVA_OPTS`.

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
* `indir`: call through `Method#invoke`
* `all`: shorthand to apply all available instrumentations (except `gep`)

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
for an example of such a hook. An example for a sanitizer can be found in
[ExamplePathTraversalFuzzerHooks.java](https://github.com/CodeIntelligenceTesting/jazzer/tree/main/examples/src/main/java/com/example/ExamplePathTraversalFuzzerHooks.java).

Method hooks can be declared using the `@MethodHook` annotation defined in the `com.code_intelligence.jazzer.api` package,
which is contained in `jazzer_api_deploy.jar` (binary release) or built by the target `//agent:jazzer_api_deploy.jar` (Bazel).
It is also available from
[Maven Central](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).
See the [javadocs of the `@MethodHook` API](https://codeintelligencetesting.github.io/jazzer-api/com/code_intelligence/jazzer/api/MethodHook.html)
for more details.

To use the compiled method hooks they have to be available on the classpath provided by `--cp` and can then be loaded by providing the
flag `--custom_hooks`, which takes a colon-separated list of names of classes to load hooks from.
If a hook is meant to be applied to a class in the Java standard library, it has to be loaded from a JAR file so that Jazzer can [add it to the bootstrap class loader search](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/Instrumentation.html#appendToBootstrapClassLoaderSearch-java.util.jar.JarFile-).
This list of custom hooks can alternatively be specified via the `Jazzer-Hook-Classes` attribute in the fuzz target
JAR's manifest.

### Suppressing stack traces

With the flag `--keep_going=N` Jazzer continues fuzzing until `N` unique stack traces have been encountered.

Particular stack traces can also be ignored based on their `DEDUP_TOKEN` by passing a comma-separated list of tokens
via `--ignore=<token_1>,<token2>`.

### Export coverage information

The internally gathered JaCoCo coverage information can be exported in human-readable and JaCoCo execution data format
(`.exec`). These can help identify code areas that have not been covered by the fuzzer and thus may require more
comprehensive fuzz targets or a more extensive initial corpus to reach.

The human-readable report contains coverage information, like branch and line coverage, on file level. It's useful to 
get a quick overview about the overall coverage. The flag `--coverage_report=<file>` can be used to generate it.

Similar to the JaCoCo `dump` command, the flag `--coverage_dump=<file>` specifies a coverage dump file, often called
`jacoco.exec`, that is generated after the fuzzing run. It contains a binary representation of the gathered coverage 
data in the JaCoCo format.

The JaCoCo `report` command can be used to generate reports based on this coverage dump. The JaCoCo CLI tools are 
available on their [GitHub release page](https://github.com/jacoco/jacoco/releases) as `zip` file. The report tool is 
located in the `lib` folder and can be used as described in the JaCoCo 
[CLI documentation](https://www.eclemma.org/jacoco/trunk/doc/cli.html). For example the following command generates an 
HTML report in the folder `report` containing all classes available in `classes.jar` and their coverage as captured in 
the export `coverage.exec`. Source code to include in the report is searched for in `some/path/to/sources`. 
After execution the `index.html` file in the output folder can be opened in a browser.
```shell
java -jar path/to/jacococli.jar report coverage.exec \
  --classfiles classes.jar \
  --sourcefiles some/path/to/sources \
  --html report \
  --name FuzzCoverageReport
```

## Advanced fuzz targets

### Fuzzing with Native Libraries

Jazzer supports fuzzing of native libraries loaded by the JVM, for example via `System.load()`. For the fuzzer to get
coverage feedback, these libraries have to be compiled with `-fsanitize=fuzzer-no-link`.

Additional sanitizers such as AddressSanitizer or UndefinedBehaviorSanitizer are often desirable to uncover bugs inside
the native libraries. The required compilation flags for native libraries are as follows:
 - *AddressSanitizer*: `-fsanitize=fuzzer-no-link,address`
 - *UndefinedBehaviorSanitizer*: `-fsanitize=fuzzer-no-link,undefined` (add `-fno-sanitize-recover=all` to crash on UBSan reports)

Then, use the appropriate driver `//:jazzer_asan` or `//:jazzer_ubsan`.

**Note:** Sanitizers other than AddressSanitizer and UndefinedBehaviorSanitizer are not yet supported.
Furthermore, due to the nature of the JVM's GC, LeakSanitizer reports too many false positives to be useful and is thus disabled.

The fuzz targets `ExampleFuzzerWithNativeASan` and `ExampleFuzzerWithNativeUBSan` in the `examples/` directory contain
minimal working examples for fuzzing with native libraries. Also see `TurboJpegFuzzer` for a real-world example.

### Fuzzing with Custom Mutators

LibFuzzer API offers two functions to customize the mutation strategy which is especially useful when fuzzing functions
that require structured input. Jazzer does not define `LLVMFuzzerCustomMutator` nor `LLVMFuzzerCustomCrossOver` and
leaves the mutation strategy entirely to libFuzzer. However, custom mutators can easily be integrated by
compiling a mutator library which defines `LLVMFuzzerCustomMutator` (and optionally `LLVMFuzzerCustomCrossOver`) and
pre-loading the mutator library:

```bash
# Using Bazel:
LD_PRELOAD=libcustom_mutator.so bazel run //:jazzer -- <arguments>
# Using the binary release:
LD_PRELOAD=libcustom_mutator.so ./jazzer <arguments>
```

## Credit

The following developers have contributed to Jazzer before its public release:

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
