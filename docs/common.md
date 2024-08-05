## Common options and workflows

* [Recommended JVM options](#recommended-jvm-options)
* [Passing arguments](#passing-arguments)
* [Reproducing a finding](#reproducing-a-finding)
* [Minimizing a crashing input](#minimizing-a-crashing-input)
* [Parallel execution](#parallel-execution)
* [Autofuzz mode](#autofuzz-mode)
* [Docker](#docker)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->

### Recommended JVM options

The following JVM settings are recommended for running Jazzer within JUnit.
The `jazzer` launcher binary sets them automatically.

* `-XX:-OmitStackTraceInFastThrow` ensures that stack traces are emitted even on hot code paths.
  This may hurt performance if your fuzz test frequently throws and catches exceptions, but also helps find flaky bugs.
* `-XX:+UseParallelGC` optimizes garbage collection for high throughput rather than low latency.
* `-XX:+CriticalJNINatives` is supported with JDK 17 and earlier and improves the runtime performance of Jazzer's instrumentation.
* `-XX:+EnableDynamicAgentLoading` silences a warning with JDK 21 and later triggered by the Java agent that Jazzer attaches to instrument the fuzzed code.

### Passing arguments

Jazzer provides many configuration settings. An up-to-date list can be found by running Jazzer with the `--help` flag.

The value of a setting item `some_opt` is obtained from the following sources in increasing order of precedence:

- the default value
- `META-INF/MANIFEST.MF` attribute `Jazzer-Some-Opt` on the classpath
- the `JAZZER_SOME_OPT` environment variable
- the `jazzer.some_opt` system property
- the `jazzer.some_opt` JUnit configuration parameter
- the `--some_opt` CLI parameter

### Reproducing a finding

When Jazzer manages to find an input that causes an uncaught exception or a failed assertion, it prints a Java stack trace and creates two files that aid in reproducing the crash without Jazzer:

* `crash-<sha1_of_input>` contains the raw bytes passed to the fuzz target (just as with libFuzzer C/C++ fuzz targets).
  The crash can be reproduced with Jazzer by passing the path to the crash file as the only positional argument.
* `Crash-<sha1_of_input>.java` contains a class with a `main` function that invokes the fuzz target with the crashing input.
  This is especially useful if using `FuzzedDataProvider` as the raw bytes of the input do not directly correspond to the values consumed by the fuzz target.
  The `.java` file can be compiled with just the fuzz target and its dependencies in the classpath (plus `jazzer_standalone.jar` or `com.code-intelligence:jazzer-api:<version>` if using `FuzzedDataProvider`).

### Minimizing a crashing input

Every crash stack trace is accompanied by a `DEDUP_TOKEN` that uniquely identifies the relevant parts of the stack trace.
This value is used by libFuzzer while minimizing a crashing input to ensure that the smaller inputs reproduce the "same" bug.
To minimize a crashing input, execute Jazzer with the following arguments in addition to `--cp` and `--target_class`:

```bash
-minimize_crash=1 <path/to/crashing_input>
```

### Parallel execution

libFuzzer offers the `-fork=N` and `-jobs=N` flags for parallel fuzzing, both of which are also supported by Jazzer.

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

Under the hood, Jazzer tries various ways of creating objects from the fuzzer input.
For example, if a parameter is an interface or an abstract class, it will look for all concrete implementing classes on the classpath.
Jazzer can also create objects from classes that follow the [builder design pattern](https://www.baeldung.com/creational-design-patterns#builder) or have a default constructor and use setters to set the fields.

Creating objects from fuzzer input can lead to many reported exceptions.
Jazzer addresses this issue by ignoring exceptions that the target method declares to throw.
In addition to that, you can provide a list of exceptions to be ignored during fuzzing via the `--autofuzz_ignore` flag in the form of a comma-separated list.
You can specify concrete exceptions (e.g., `java.lang.NullPointerException`), in which case also subclasses of these exception classes will be ignored, or glob patterns to ignore all exceptions in a specific package (e.g. `java.lang.*` or `com.company.**`).

### Docker

**Outdated: The public docker images are outdated and the whole approach needs to be validated.** 

The "distroless" Docker image [cifuzz/jazzer](https://hub.docker.com/r/cifuzz/jazzer) includes a recent Jazzer release together with OpenJDK 17.
Mount a directory containing your compiled fuzz target into the container under `/fuzzing` and use it like a GitHub release binary by running:

```sh
docker run -v path/containing/the/application:/fuzzing cifuzz/jazzer --cp=<classpath> --target_class=<fuzz test class>
```

If Jazzer produces a finding, the input that triggered it will be available in the same directory.


#### Autofuzz

You can use Docker to try out Jazzer's Autofuzz mode, in which it automatically generates arguments to a given Java function and reports unexpected exceptions and detected security issues:

```
docker run -it cifuzz/jazzer-autofuzz \
   com.mikesamuel:json-sanitizer:1.2.0 \
   com.google.json.JsonSanitizer::sanitize \
   --autofuzz_ignore=java.lang.ArrayIndexOutOfBoundsException
```

Here, the first two arguments are the Maven coordinates of the Java library and the fully qualified name of the Java function to be fuzzed in "method reference" form.
The optional `--autofuzz_ignore` flag takes a list of uncaught exception classes to ignore.

After a few seconds, Jazzer should trigger an `AssertionError`, reproducing a bug it found in this library that has since been fixed.
