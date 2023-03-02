## Advanced options

* [Passing JVM arguments](#passing-jvm-arguments)
* [Coverage instrumentation](#coverage-instrumentation)
* [Trace instrumentation](#trace-instrumentation)
* [Value profile](#value-profile)
* [Custom hooks](#custom-hooks)
* [Suppressing stack traces](#suppressing-stack-traces)
* [Export coverage information](#export-coverage-information)
* [Native libraries](#native-libraries)
* [Fuzzing mutators](#fuzzing-mutators)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->

Various command line options are available to control the instrumentation and fuzzer execution.
Since Jazzer is a libFuzzer-compiled binary, all positional and single dash command-line options are parsed by libFuzzer.
Therefore, all Jazzer options are passed via double dash command-line flags, i.e., as `--option=value` (note the `=` instead of a space).

A full list of command-line flags can be printed with the `--help` flag.
For the available libFuzzer options please refer to [its documentation](https://llvm.org/docs/LibFuzzer.html) for a detailed description.

### Passing JVM arguments

When Jazzer is started using the `jazzer` binary, it starts a JVM in which it executes the fuzz target.
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

Arguments specified with `--jvm_args` take precedence over those in `JAVA_OPTS`.

### Coverage instrumentation

The Jazzer agent inserts coverage markers into the JVM bytecode during class loading.
libFuzzer uses this information to guide its input mutations towards increased coverage.

It is possible to restrict instrumentation to only a subset of classes with the `--instrumentation_includes` flag.
This is especially useful if coverage inside specific packages is of higher interest, e.g., the user library under test rather than an external parsing library in which the fuzzer is likely to get lost.
Similarly, there is `--instrumentation_excludes` to exclude specific classes from instrumentation.
Both flags take a list of glob patterns for the java class name separated by colon:

```bash
--instrumentation_includes=com.my_com.**:com.other_com.** --instrumentation_excludes=com.my_com.crypto.**
```

By default, JVM-internal classes and Java as well as Kotlin standard library classes are not instrumented, so these do not need to be excluded manually.

### Trace instrumentation

The agent adds additional hooks for tracing compares, integer divisions, switch statements and array indices.
These hooks correspond to [clang's data flow hooks](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow).
The particular instrumentation types to apply can be specified using the `--trace` flag, which accepts the following values:

* `cov`: AFL-style edge coverage
* `cmp`: compares (int, long, String) and switch cases
* `div`: divisors in integer divisions
* `gep`: constant array indexes
* `indir`: call through `Method#invoke`
* `all`: shorthand to apply all available instrumentations (except `gep`)

Multiple instrumentation types can be combined with a colon (Linux, macOS) or a semicolon (Windows).

### Value profile

The run-time flag `-use_value_profile=1` enables [libFuzzer's value profiling mode](https://llvm.org/docs/LibFuzzer.html#value-profile).
When running with this flag, the feedback about compares and constants received from Jazzer's trace instrumentation is associated with the particular bytecode location and used to provide additional coverage instrumentation.
See [ExampleValueProfileFuzzer.java](../examples/src/main/java/com/example/ExampleValueProfileFuzzer.java) for a fuzz target that would be very hard to fuzz without value profile.

### Custom hooks

In order to obtain information about data passed into functions such as `String.equals` or `String.startsWith`, Jazzer hooks invocations to these methods.
This functionality is also available to fuzz targets, where it can be used to implement custom sanitizers or stub out methods that block the fuzzer from progressing (e.g. checksum verifications or random number generation).
See [ExampleFuzzerHooks.java](../examples/src/main/java/com/example/ExampleFuzzerHooks.java) for an example of such a hook.
An example for a sanitizer can be found in [ExamplePathTraversalFuzzerHooks.java](../examples/src/main/java/com/example/ExamplePathTraversalFuzzerHooks.java).

Method hooks can be declared using the `@MethodHook` annotation defined in the `com.code_intelligence.jazzer.api` package, which is contained in `jazzer_standalone.jar` (binary release) or in the Maven artifact [`com.code-intelligence:jazzer-api`](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).
See the [javadocs of the `@MethodHook` API](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/MethodHook.html) for more details.

To use the compiled method hooks, they have to be available on the classpath provided by `--cp` and can then be loaded by providing the flag `--custom_hooks`, which takes a colon-separated list of names of classes to load hooks from.
Hooks have to be loaded from separate JAR files so that Jazzer can [add it to the bootstrap class loader search](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/Instrumentation.html#appendToBootstrapClassLoaderSearch-java.util.jar.JarFile-).
The list of custom hooks can alternatively be specified via the `Jazzer-Hook-Classes` attribute in the fuzz target JAR's manifest.

### Suppressing stack traces

With the flag `--keep_going=N` Jazzer continues fuzzing until `N` unique stack traces have been encountered.

Particular stack traces can also be ignored based on their `DEDUP_TOKEN` by passing a comma-separated list of tokens via `--ignore=<token_1>,<token2>`.

### Export coverage information

The internally gathered JaCoCo coverage information can be exported in human-readable and JaCoCo execution data format (`.exec`).
These can help identify code areas that have not been covered by the fuzzer and thus may require more comprehensive fuzz targets or a more extensive initial corpus to reach.

The human-readable report contains coverage information, like branch and line coverage, on file level.
It's useful to get a quick overview about the overall coverage. The flag `--coverage_report=<file>` can be used to generate it.

Similar to the JaCoCo `dump` command, the flag `--coverage_dump=<file>` specifies a coverage dump file, often called `jacoco.exec`, that is generated after the fuzzing run. It contains a binary representation of the gathered coverage data in the JaCoCo format.

The JaCoCo `report` command can be used to generate reports based on this coverage dump.
The JaCoCo CLI tools are available on their [GitHub release page](https://github.com/jacoco/jacoco/releases) as `zip` file.
The report tool is located in the `lib` folder and can be used as described in the JaCoCo [CLI documentation](https://www.eclemma.org/jacoco/trunk/doc/cli.html).
For example the following command generates an HTML report in the folder `report` containing all classes available in `classes.jar` and their coverage as captured in the export `coverage.exec`.
Source code to include in the report is searched for in `some/path/to/sources`.
After execution the `index.html` file in the output folder can be opened in a browser.
```shell
java -jar path/to/jacococli.jar report coverage.exec \
  --classfiles classes.jar \
  --sourcefiles some/path/to/sources \
  --html report \
  --name FuzzCoverageReport
```

### Native libraries

Jazzer supports fuzzing of native libraries loaded by the JVM, for example via `System.load()`.
For the fuzzer to get coverage feedback, these libraries have to be compiled with `-fsanitize=fuzzer-no-link`.

Additional sanitizers such as AddressSanitizer or UndefinedBehaviorSanitizer are often desirable to uncover bugs inside the native libraries.
The required compilation flags for native libraries are as follows:
- *AddressSanitizer*: `-fsanitize=fuzzer-no-link,address`
- *UndefinedBehaviorSanitizer*: `-fsanitize=fuzzer-no-link,undefined` (add `-fno-sanitize-recover=all` to crash on UBSan reports)

Then, start Jazzer with `--asan` and/or `--ubsan` to automatically preload the sanitizer runtimes.
Jazzer defaults to using the runtimes associated with `clang` on the `PATH`.
If you used a different compiler to compile the native libraries, specify it with `CC` to override this default.
If no compiler is available in your runtime environment (e.g. in OSS-Fuzz) but you have a directory that contains the required sanitier libraries, specify its path in `JAZZER_NATIVE_SANITIZERS_DIR`.

**Note:** On macOS, you may see Gatekeeper warnings when using `--asan` and/or `--ubsan` since these flags cause the native sanitizer libraries to be preloaded into the codesigned `java` executable via `DYLD_INSERT_LIBRARIES`.

Sanitizers other than AddressSanitizer and UndefinedBehaviorSanitizer are not yet supported.
Furthermore, due to the nature of the JVM's GC, LeakSanitizer reports too many false positives to be useful and is thus disabled.

The fuzz targets `ExampleFuzzerWithASan` and `ExampleFuzzerWithUBSan` in the [`examples`](../examples/src/main/java/com/example) directory contain minimal working examples for fuzzing with native libraries.
Also see `TurboJpegFuzzer` for a real-world example.

### Fuzzing mutators

LibFuzzer API offers two functions to customize the mutation strategy which is especially useful when fuzzing functions that require structured input.
Jazzer does not define `LLVMFuzzerCustomMutator` nor `LLVMFuzzerCustomCrossOver` and leaves the mutation strategy entirely to libFuzzer.
However, custom mutators can easily be integrated by compiling a mutator library which defines `LLVMFuzzerCustomMutator` (and optionally `LLVMFuzzerCustomCrossOver`) and pre-loading the mutator library:

```bash
# Using Bazel:
LD_PRELOAD=libcustom_mutator.so bazel run //:jazzer -- <arguments>
# Using the binary release:
LD_PRELOAD=libcustom_mutator.so ./jazzer <arguments>
```

