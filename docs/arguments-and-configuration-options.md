# Arguments and Configuration Options
Jazzer provides many configuration settings.
An up-to-date list can be found by running standalone Jazzer with the `--help` flag.

The value of a setting item `some_opt` is obtained from the following sources in increasing order of precedence:

- the default value
- `META-INF/MANIFEST.MF` attribute `Jazzer-Some-Opt` on the classpath
- the `JAZZER_SOME_OPT` environment variable
- the `jazzer.some_opt` system property
- the `jazzer.some_opt` JUnit configuration parameter (e.g. in `resources/junit-platform.properties` of the test sources)
- the `--some_opt` CLI parameter to Jazzer standalone

Some parameters only have an effect when used with standalone Jazzer binary (marked as *standalone only*), or only in fuzzing mode (marked as *fuzzing only*), or exist only as environment variables (marked as *environment variable only*).


- **additional_classes_excludes** [list, separator=`':'`, default=""]
  - Glob patterns matching names of classes from Java that are not in your jar file, but may be included in your program. 
  Example: `JAZZER_ADDITIONAL_CLASSES_EXCLUDES=org.example.NotHere:org.example.AlsoNotBelow.**`
  
- **additional_jvm_args** [list, separator=`':'`, default=""] (*standalone only*)
  - Additional arguments to pass to the JVM (separator can be escaped with `\\`)
  
- **agent_path** [string, default=""] (*standalone only*)
  - Custom path to `jazzer_agent_deploy.jar`
  
- **android_bootpath_classes_overrides** [string, default=""]
  - Used for fuzzing classes loaded in through the bootstrap class loader on Android.
  Full path to jar file with the instrumented versions of the classes you want to override.
  
- **android_init_options** [string, default=""] (*standalone only*)
  - Which libraries to use when initializing ART 
  
- **asan** [bool, default="false"]
  - Allow fuzzing of native libraries compiled with `-fsanitize=address`.
  See [here](advanced.md#native-libraries) for more details.
  
- **autofuzz** [string, default=""] (*DEPRECATED*)
    - Fully qualified reference (optionally with a Javadoc-style signature) to a method on the class path to be fuzzed with automatically generated arguments
    - Examples: `java.lang.System.out::println`, `java.lang.String::new(byte[])`
	
- **autofuzz_ignore** [list, separator=`','`, default=""] (*DEPRECATED*)
  - Fully qualified names of exception classes to ignore during fuzzing
  
- **command_line** [bool, default="false"]
  - Whether Jazzer is running a JUnit fuzz test from the command line
  
- **conditional_hooks** [bool, default="false"]
  - Whether hook instrumentation should add a check for JazzerInternal#hooksEnabled before executing hooks.
  Used to disable hooks during non-fuzz JUnit tests.
  
- **coverage_dump** [string, default=""]
  - Path to write a JaCoCo `.exec` file to when the fuzzer exits (if non-empty).
  See [here](advanced.md#export-coverage-information) for more details.
  
- **coverage_report** [string, default=""]
  - Path to write a human-readable coverage report to when the fuzzer exits (if non-empty)
  
- **cp** [list, separator=`':'`, default=""] (*standalone only*)
  - The class path to use for fuzzing

- **custom_hooks** [list, separator=`':'`, default=""]
  - Names of classes to load custom hooks from
  
- **custom_hook_excludes** [list, separator=`':'`, default=""]
  - Glob patterns matching names of classes that should not be instrumented with hooks (custom and built-in)
  
- **custom_hook_includes** [list, separator=`':'`, default=""]
  - Glob patterns matching names of classes to instrument with hooks (custom and built-in)
  
- **dedup** [bool, default="true"]
  - Compute and print a deduplication token for every finding
  
- **disabled_hooks** [list, separator=`':'`, default=""]
  - Names of classes from which hooks (custom or built-in) should not be loaded from
  - Example: to disable the `ServerSideRequestForgery` and `RegexInjection` sanitizers use this environment variable when running Jazzer:
    - `JAZZER_DISABLED_HOOKS=com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery:com.code_intelligence.jazzer.sanitizers.RegexInjection`
  
- **dump_classes_dir** [string, default=""]
  - Directory to dump instrumented `.class` files into (if non-empty)
  
- **fuzz** [bool, default=`false`]
  - Run in fuzzing mode (use `true`) or regression mode (use `false`).
  Defaults to `true` in *standalone* mode
  
- **help** [bool, default="false"] (*standalone only*)
  - Show the list of all available arguments
  
- **hooks** [bool, default="true"]
  - Apply fuzzing instrumentation (use 'trace' for finer-grained control)
  - Example: `JAZZER_HOOKS=0` - to turn off all instrumentation
  
- **hwasan** [bool, default="true"]
  - Allow fuzzing of native libraries compiled with hwasan
  
- **id_sync_file** [string, default=""]
  - A file used by Jazzer subprocesses to coordinate coverage instrumented.
  If not set, Jazzer will create a temporary file and pass it to subprocesses.
  
- **ignore** [list, separator=`','`, default=""]
  - Hex strings representing deduplication tokens of findings that should be ignored
  
- **instrument** [list, separator=`','`, default=""]
  - Glob patterns matching names of classes that should be instrumented for fuzzing.
  This sets both `instrumentation_includes` and `custom_hook_includes`, depending on the mode (regression test or fuzzing). 
  See [here](advanced.md#coverage-instrumentation) for more details.
  
- **instrument_only** [list, separator=`','`, default=""]
  - Comma separated list of jar files to instrument.
  No fuzzing is performed.
  
- **instrumentation_excludes** [list, separator=`':'`, default=""]
  - Glob patterns matching names of classes that should not be instrumented for fuzzing
  See [here](advanced.md#coverage-instrumentation) for more details.
  
- **jvm_args** [list, separator=`':'`, default=""] (*standalone only*)
  - Arguments to pass to the JVM (separator can be escaped with `\\`).
  See [here](advanced.md#passing-jvm-arguments) for more details.
  
- **instrumentation_includes** [list, separator=`':'`, default=""]
  - Glob patterns matching names of classes to instrument for fuzzing.
  See [here](advanced.md#coverage-instrumentation) for more details.

- **JAZZER_COVERAGE** [bool, default="false"] (*environment variable only*)
  - In regression mode, controls which folders are used for coverage computation.
    - `false` (default): Use only thej crash file folder.
	- `true`: Use both the crash file folder and the corpus folder.

- **JAZZER_SSRF_PERMISSIVE_UNTIL_CONFIGURED** [bool, default="false"] (*environment variable only*)
  - When set to `true`, the SSRF sanitizer will allow all outgoing requests until it is explicitly configured with BugDetectors.allowNetworkConnections(...).
  This is useful to avoid false positives in multithreaded applications that make network requests after the fuzzing has started, but before the user had a chance to configure the sanitizer.

- **keep_going** [uint64, default="1"]
  - Number of distinct findings after which the fuzzer should stop.
  See [here](advanced.md#keep-going) for more details.
  
- **list_fuzz_tests** [list, separator=`':'`, default=""] (*JUnit only*)
  - Prints all fuzz test names in the given classes. If no classes are provided, all directories (but not JAR files) on the classpath are scanned for tests.
  If this parameter is given, all others are ignored.
  
- **max_duration** [string, default=""]
  - Sets the maximum fuzzing duration (e.g., '30s', '2m', '1h'; empty = unlimited). For JUnit tests, overrides `@FuzzTest(maxDuration)`; for standalone, translates to `-max_total_time` flag to libFuzzer, unless that flag is already present.
  
- **merge_inner** [bool, default="false"]
  - Whether this is a subprocess created by libFuzzer's `-merge` mode.
  
- **mutator_cross_over_frequency** [uint64, default="100"] (*only when using mutation framework*)
  - Frequency of cross-over mutations actually being executed when the cross-over function is picked by the underlying fuzzing engine (~1/2 of all mutations), other invocations perform type specific mutations via the mutator framework. (0 = disabled, 1 = every call, 2 = every other call, etc.).
  
- **mutator_framework** [bool, default="true"]
  - Use the internal mutator framework to generate inputs
  
- **native** [bool, default="false"]
  - Allow fuzzing of native libraries compiled with `-fsanitize=fuzzer` (implied by `asan` and `ubsan`)
  See [here](advanced.md#native-libraries) for more details.
  
- **reproducer_path** [string, default="."]
  - Directory in which stand-alone Java reproducers are stored for each finding
  
- **target_args** [list, separator=`' '`, default=""]
  - Arguments to pass to the fuzz target's `fuzzerInitialize` method
  
- **target_class** [string, default=""]
  - Fully qualified name of the fuzz target class (required unless -autofuzz is specified)
  
- **target_method** [string, default=""]
  - The name of the `@FuzzTest` to execute in the class specified by `-target_class`
  
- **trace** [list, separator=`':'`, default=""]
  - Types of instrumentation to apply: cmp, cov, div, gep (disabled by default), indir, native.
  See [here](advanced.md#trace-instrumentation) for more details.
  
- **ubsan** [bool, default="false"]
  - Allow fuzzing of native libraries compiled with `-fsanitize=undefined` used for JUnit fuzz tests.
  See [here](advanced.md#native-libraries) for more details.
  
- **version** [bool, default="false"]
  - Print version information
