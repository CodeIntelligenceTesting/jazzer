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
  <a href="https://github.com/CodeIntelligenceTesting/jazzer/actions/workflows/run-all-tests-main.yml?query=branch%3Amain">
    <img src="https://img.shields.io/github/actions/workflow/status/CodeIntelligenceTesting/jazzer/run-all-tests-main.yml?branch=main&logo=github" alt="CI status">
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

> [!IMPORTANT]
> Hello users!
>
> We are thrilled to announce that **Jazzer** is now back under the **Apache 2.0 license**!
>
> A year ago, we temporarily stopped maintaining Jazzer as open source. 
> During this time, we received incredible feedback, support, and ideas from
> the community, which motivated us to find a way to bring Jazzer back to the
> open-source world.
>
> Thanks to your enthusiasm and contributions, and a special callout to the 
> [OSS-Fuzz](https://github.com/google/oss-fuzz) team 🚀.
> 
> Visit [code-intelligence.com](https://code-intelligence.com) for more 
> information.
>
> The Code Intelligence team

Jazzer is a coverage-guided, in-process fuzzer for the JVM platform developed by [Code Intelligence](https://code-intelligence.com).
It is based on [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and brings many of its instrumentation-powered mutation features to the JVM.

Jazzer currently supports the following platforms:
* Linux x86_64
* macOS 12+ x86_64 & arm64
* Windows x86_64

## Using Jazzer via...

### JUnit 5

The following steps assume that JUnit 5.9.0 or higher is set up for your project, for example based on the official [junit5-samples](https://github.com/junit-team/junit5-samples).

1. Add a dependency on `com.code-intelligence:jazzer-junit:<latest version>`.
   All Jazzer Maven artifacts are signed with [this key](deploy/maven.pub).
2. Add a new *fuzz test* to a new or existing test class: a method annotated with [`@FuzzTest`](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-junit/com/code_intelligence/jazzer/junit/FuzzTest.html) and at least one parameter.
   Using a single parameter of type [`FuzzedDataProvider`](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html), which provides utility functions to produce commonly used Java values, or `byte[]` is recommended for optimal performance and reproducibility of findings.
3. Assuming your test class is called `com.example.MyFuzzTests`, create the *inputs directory* `src/test/resources/com/example/MyFuzzTestsInputs`.
4. Run a fuzz test with the environment variable `JAZZER_FUZZ` set to `1` to let the fuzzer rapidly try new sets of arguments.
   If the fuzzer finds arguments that make your fuzz test fail or even trigger a security issue, it will store them in the inputs directory.
   In this mode, only a single fuzz test is executed per test run (see [#599](https://github.com/CodeIntelligenceTesting/jazzer/issues/599) for details).
5. Run the fuzz test without `JAZZER_FUZZ` set to execute it only on the inputs in the inputs directory.
   This mode, which behaves just like a traditional unit test, ensures that issues previously found by the fuzzer remain fixed and can also be used to debug the fuzz test on individual inputs.

A simple property-based fuzz test could look like this (excluding imports):

```java
class ParserTests {
   @Test
   void unitTest() {
      assertEquals("foobar", SomeScheme.decode(SomeScheme.encode("foobar")));
   }

   @FuzzTest
   void fuzzTest(FuzzedDataProvider data) {
      String input = data.consumeRemainingAsString();
      assertEquals(input, SomeScheme.decode(SomeScheme.encode(input)));
   }
}
```

A complete Maven example project can be found in [`examples/junit`](examples/junit).

### GitHub releases

You can also use GitHub release archives to run a standalone Jazzer binary that starts its own JVM configured for fuzzing:

1. Download and extract the latest release from the [GitHub releases page](https://github.com/CodeIntelligenceTesting/jazzer/releases).
2. Add a new class to your project with a <code>public static void fuzzerTestOneInput(<a href="https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html">FuzzedDataProvider</a> data)</code> method.
3. Compile your fuzz test with `jazzer_standalone.jar` on the classpath.
4. Run the `jazzer` binary (`jazzer.exe` on Windows), specifying the classpath and fuzz test class:

```shell
./jazzer --cp=<classpath> --target_class=<fuzz test class>
```

If you see an error saying that `libjvm.so` has not been found, make sure that `JAVA_HOME` points to a JDK.

The [`examples`](examples/src/main/java/com/example) directory includes both toy and real-world examples of fuzz tests.

### Bazel

Support for Jazzer is available in [rules_fuzzing](https://github.com/bazelbuild/rules_fuzzing), the official Bazel rules for fuzzing.
See [the README](https://github.com/bazelbuild/rules_fuzzing#java-fuzzing) for instructions on how to use Jazzer in a Java Bazel project.

### OSS-Fuzz

[Code Intelligence](https://code-intelligence.com) and Google have teamed up to bring support for Java, Kotlin, and other JVM-based languages to [OSS-Fuzz](https://github.com/google/oss-fuzz), Google's project for large-scale fuzzing of open-source software.
Read [the OSS-Fuzz guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/) to learn how to set up a Java project.

## Building from source

Information on building and testing Jazzer for development can be found in [CONTRIBUTING.md](CONTRIBUTING.md)

## Further documentation

* [Common options and workflows](docs/common.md)
* [Advanced techniques](docs/advanced.md)

## Findings

A list of security issues and bugs found by Jazzer is maintained [here](docs/findings.md).
If you found something interesting and the information is public, please send a PR to add it to the list.

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

[`FuzzedDataProvider`]: https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html
