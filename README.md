<div align="center">
  <a href="https://code-intelligence.com"><img src="https://www.code-intelligence.com/hubfs/Logos/CI%20Logos/Jazzer_einfach.png" height=150px alt="Jazzer by Code Intelligence">
</a>
  <h1>Jazzer</h1>
  <p>Fuzz Testing for the JVM</p>
  <a href="https://github.com/CodeIntelligenceTesting/jazzer/releases">
    <img src="https://img.shields.io/github/v/release/CodeIntelligenceTesting/jazzer" alt="Releases">
  </a>
  <a href="https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer">
    <img src="https://img.shields.io/maven-central/v/com.code-intelligence/jazzer" alt="Maven Central">
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/jazzer/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/CodeIntelligenceTesting/jazzer" alt="License">
  </a>

  <br />

<a href="https://www.code-intelligence.com/" target="_blank">Website</a>
|
<a href="https://www.code-intelligence.com/blog" target="_blank">Blog</a>
|
<a href="https://twitter.com/CI_Fuzz" target="_blank">Twitter</a>
</div>

Jazzer is a coverage-guided, in-process fuzzer for the JVM platform developed by [Code Intelligence](https://code-intelligence.com).
It is based on [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and brings many of its instrumentation-powered mutation features to the JVM.

Jazzer currently supports the following platforms:
* Linux x86_64
* macOS 12+ x86_64 & arm64
* Windows x86_64

## Setup

Jazzer integrates seamlessly with JUnit (version 5.9.0 or newer), allowing you to write fuzz tests alongside your regular unit tests.
The recommended way to get started is by adding the `jazzer-junit` dependency to your project.
This package is available on [Maven Central](https://central.sonatype.com/artifact/com.code-intelligence/jazzer-junit) and is signed with [this key](deploy/maven.pub).

You can use Jazzer with popular build tools:

### Maven

Add the following to your `pom.xml`:

```xml
<dependency>
    <groupId>com.code-intelligence</groupId>
    <artifactId>jazzer-junit</artifactId>
    <version>LATEST VERSION</version>
</dependency>
```

A complete example project using Maven is available in [`examples/junit`](examples/junit).

### Gradle

Include Jazzer in your `build.gradle`:

```gradle
implementation group: 'com.code-intelligence', name: 'jazzer-junit', version: '<LATEST VERSION>'
```

### Bazel

Jazzer is supported via [rules_fuzzing](https://github.com/bazelbuild/rules_fuzzing), the official Bazel rules for fuzzing.
For setup instructions, see [the README](https://github.com/bazelbuild/rules_fuzzing#java-fuzzing).

With Jazzer set up, you can start writing fuzz tests and benefit from automated bug discovery and improved code coverage.

## Writing fuzz tests

To write a fuzz test, add a method to your test class and annotate it with [`@FuzzTest`](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-junit/com/code_intelligence/jazzer/junit/FuzzTest.html).
Jazzer will automatically generate and mutate inputs for your method parameters.
You can use primitives, strings, arrays, and many standard library classes.
See the [mutation framework documentation](docs/mutation-framework.md#supported-types) for details.
To run a fuzz test in [fuzzing mode](#fuzzing-mode), set environment variable `JAZZER_FUZZ` to a truthy value:
```bash
JAZZER_FUZZ=1 mvn test org.example.ParserTests
```

Here is an example that demonstrates fuzzing security-relevant logic:

```java
package org.example;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ParserTests {
    @Test
    void unitTest() {
        assertEquals("foobar", SomeScheme.decode(SomeScheme.encode("foobar")));
    }

    @FuzzTest
    void fuzzTest_decode(@NotNull String input) {
        assertEquals(input, SomeScheme.decode(SomeScheme.encode(input)));
    }
	
    @FuzzTest
    void fuzzTest_decodeWithN(@NotNull @WithUtf8Length(min=10, max=200) String input, @InRange(min=-10, max=10) int n) {
        assertEquals(input, SomeScheme.decode(SomeScheme.encode(input)));
        assertTrue(n >= -10 && n <= 10);
    }
}
```
A complete Maven example project can be found in [examples/junit](examples/junit).


## Running Jazzer

Jazzer can be run in two ways: using the JUnit integration or by using Jazzer standalone.

### Using JUnit integration

To run fuzz tests, use your build system as you would for regular tests.
Methods annotated with `@FuzzTest` can be executed in two modes: regression mode and fuzzing mode.


#### Regression mode

In regression mode, Jazzer runs each fuzz test with crashing inputs found in its corresponding [*inputs directory*](#inputs-directory).
This mode behaves like a traditional unit test: it verifies that previously discovered issues remain fixed and helps debug the fuzz test with specific inputs.
By default, Jazzer operates in regression mode unless fuzzing mode is explicitly enabled.

If you want that Jazzer also uses the inputs from the [*generated corpus directory*](#generated-corpus-directory), set the environment variable `JAZZER_COVERAGE=1`.


#### Fuzzing mode

This mode helps uncover new bugs and improve test coverage.
Enable fuzzing mode by setting the environment variable `JAZZER_FUZZ=1` before running your tests.
Jazzer will execute a single fuzz test, automatically generating and mutating inputs to maximize code coverage and find bugs.
If Jazzer discovers an input that generates new coverage, it is stored in the [*generated corpus directory*](#generated-corpus-directory) of the fuzz test.
If Jazzer discovers an input that causes a fuzz test to fail (such as an uncaught exception or a triggered sanitizer), it stores the crashing input in the [*inputs directory*](#inputs-directory).


### Jazzer standalone
There are two ways to use Jazzer standalone: by calling the Jazzer main class directly or by using the `jazzer` binary.

#### Calling the Jazzer main class directly

To call Jazzer directly you need to pass it the project classpath, the path to the `jazzer.jar` and `jazzer-junit.jar`
along with the Jazzer main class `com.code_intelligence.jazzer.Jazzer` and target class that contains the Fuzz Test.

```shell
java -cp <classpath>;<path/to/jazzer.jar>;<path/to/jazzer-junit.jar> com.code_intelligence.jazzer.Jazzer --target_class=<fuzz-test-class> [args...]
```

Optionally you can add other Jazzer arguments with double dash command-line flags.
Because Jazzer is based on libFuzzer, all available libFuzzer arguments can be added with single dash command-line flags.
Please refer to [libFuzzer](https://llvm.org/docs/LibFuzzer.html) for documentation.

#### Using the `jazzer` binary
Jazzer is available as a standalone binary from the GitHub release archives that starts its own JVM configured for fuzzing:

1. Download and extract the latest release from the [GitHub releases page](https://github.com/CodeIntelligenceTesting/jazzer/releases).
2. Add a new class to your project with a `public static void fuzzerTestOneInput(String par1, int par2, int[] par3, ...)` method, with the parameters you want to use in the fuzz test.
3. Compile your fuzz test with `jazzer_standalone.jar` on the classpath.
4. Run the `jazzer` binary (`jazzer.exe` on Windows), specifying the classpath and fuzz test class:

```shell
./jazzer --cp=<classpath> --target_class=<fuzz test class>
```

If you see an error saying that `libjvm.so` has not been found, make sure that `JAVA_HOME` points to a JDK.

## Directories and files

Jazzer uses two directories to store inputs: the *generated corpus directory* and the *inputs directory*.

### Generated corpus directory

The *generated corpus directory* is where Jazzer saves inputs that generate new coverage during fuzzing.
It is located in `.cifuzz-corpus/<package>/<FuzzTestClass>/<fuzzTestMethod>`, where `<package>`, `<FuzzTestClass>`, and `<fuzzTestMethod>` correspond to the package name, class name, and method name of the fuzz test, respectively.
For example, if the fuzz test is in the class `src/test/java/com/example/ValidFuzzTestsInputs.java`, method `byteFuzz`, the corpus directory is located in `.cifuzz-corpus/com.example.ValidFuzzTestsInputs/byteFuzz`.


### Inputs directory

Any input that triggers a crash during fuzzing is saved to the *inputs directory*.
This directory is derived from the package and class name of the fuzz test.
For example, if the fuzz test is in the class `src/test/java/com/example/ValidFuzzTestsInputs.java`, method `byteFuzz`, the *inputs directory* is located in `src/test/resources/com/example/ValidFuzzTestsInputs/byteFuzz`.
If this directory does not exist, Jazzer will save crash inputs in the directory from which the tests are executed.


## Sanitizers / bug detectors

Sanitizers (also called *bug detectors*) are built-in checks that help Jazzer find security issues in your application while fuzzing.
They automatically monitor the program under test for risky behaviors, such as unsafe file access or network requests, and report them back with detailed information.
This way, you don’t just learn that an input caused a crash, but you also get insight into what kind of vulnerability it triggered.

If you've worked with C or C++ before, you may know sanitizers like [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) or [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
Jazzer sanitizers serve a similar purpose, but they are designed specifically for Java and JVM applications.
Instead of low-level memory errors, they focus on common security issues in Java software, such as **Server-Side Request Forgery** (SSRF), **File Path Traversal**, **Os Command Injection**, etc.

Sanitizers not only detect dangerous conditions but also make fuzzing smarter.
By providing feedback to the fuzzer about what they detect, they can guide input generation towards the kinds of values most likely to trigger vulnerabilities.
This makes it possible to find complex bugs more quickly and with less manual effort.

You can browse all available sanitizers in the [Jazzer codebase](sanitizers/src/main/java/com/code_intelligence/jazzer/sanitizers).
Each sanitizer can be disabled using [`disabled_hooks`](docs/arguments-and-configuration-options.md).


### Configure sanitizers using BugDetectorsAPI

Some sanitizers can also be configured at runtime using the BugDetectorsAPI to adjust how they detect vulnerabilities.
Currently, this applies to Server-Side Request Forgery and File Path Traversal sanitizers.
For details, check out the [API documentation](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/BugDetectors.html).

  
## OSS-Fuzz

[Code Intelligence](https://code-intelligence.com) and Google have teamed up to bring support for Java, Kotlin, and other JVM-based languages to [OSS-Fuzz](https://github.com/google/oss-fuzz), Google's project for large-scale fuzzing of open-source software.
Read [the OSS-Fuzz guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/) to learn how to set up a Java project.

## Trophies

A list of security issues and bugs found by Jazzer is maintained [here](docs/trophies.md).
If you found something interesting and the information is public, please send a PR to add it to the list.


## Further documentation

* [Arguments and Configuration Options](docs/arguments-and-configuration-options.md)
* [Mutation framework](docs/mutation-framework.md)
* [Advanced techniques](docs/advanced.md)
* [Building Jazzer from source](CONTRIBUTING.md)
* [JUnit integration implementation details](docs/dev-junit-implementation-details.md)
* [Autofuzz (*DEPRECATED*)](docs/autofuzz.md)


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
