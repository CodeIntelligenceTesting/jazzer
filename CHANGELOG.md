# Changelog

**Note:** Before version 1.0.0, every release may contain breaking changes.

## Version 0.11.0

* Feature: Add sanitizer for context lookups
* Feature: Add sanitizer for OS command injection
* Feature: Add sanitizer for regex injection
* Feature: Add sanitizer for LDAP injections
* Feature: Add sanitizer for arbitrary class loading 
* Feature: Guide fuzzer to generate proper map lookups keys
* Feature: Generate standalone Java reproducers for autofuzz
* Feature: Hooks targeting interfaces and abstract classes hook all implementations
* Feature: Enable multiple BEFORE and AFTER hooks for the same target
* Feature: Greatly improve performance of coverage instrumentation
* Feature: Improve performance of interactions between Jazzer and libFuzzer
* Feature: Export JaCoCo coverage dump using `--coverage_dump` flag
* Feature: Honor `JAVA_OPTS`
* API: Add `exploreState` to help the fuzzer maximize state coverage
* API: Provide `additionalClassesToHook` field in `MethodHook` annotation to hook dependent classes
* Fix: Synchronize coverage ID generation
* Fix: Support REPLACE hooks for constructors
* Fix: Do not apply REPLACE hooks in Java 6 class files

This release also includes smaller improvements and bugfixes.

## Version 0.10.0

* **Breaking change**: Use OS-specific classpath separator to split jvm_args
* Feature: Add support to "autofuzz" targets without the need to manually write fuzz targets 
* Feature: Add macOS and Windows support
* Feature: Add option to generate coverage report
* Feature: Support multiple hook annotations per hook method
* Feature: Support hooking internal classes
* Feature: Add sanitizer for insecure deserialization
* Feature: Add sanitizer for arbitrary reflective calls
* Feature: Add sanitizer for expression language injection
* Feature: Provide Jazzer and Jazzer Autofuzz docker images
* Feature: Add a stand-alone replayer to reproduce findings
* API: Add `reportFindingFromHook(Throwable finding)` to report findings from hooks
* API: Add `guideTowardsEquality(String current, String target, int id)` and `guideTowardsContainment(String haystack, String needle, int id)` to guide the fuzzer to generate more useful inputs
* API: Add `consume(FuzzedDataProvider data, Class<T> type)` to create an object instance of the given type from the fuzzer input
* API: Add multiple `autofuzz()` methods to invoke given functions with arguments automatically created from the fuzzer input
* Fixed: Prevent dependency version conflicts in fuzzed application by shading internal dependencies
* Fixed: Make initialized `this` object available to `<init>` AFTER hooks
* Fixed: Allow instrumented classes loaded by custom class loaders to find Jazzer internals

This release also includes smaller improvements and bugfixes. 

## Version 0.9.1

* **Breaking change**: The static `fuzzerTestOneInput` method in a fuzz target now has to return `void` instead of `boolean`. Fuzz targets that previously returned `true` should now throw an exception or use `assert`.
* Fixed: `jazzer` wrapper can find `jazzer_driver` even if not in the working directory
* Fixed: Switch instrumentation no longer causes an out-of-bounds read in the driver
* Feature: `assert` can be used in fuzz targets
* Feature: Coverage is now collision-free and more fine-grained (based on [JaCoCo](https://www.eclemma.org/jacoco/))
* API: Added `pickValue(Collection c)` and `consumeChar(char min, char max)` to `FuzzedDataProvider`
* API: Added `FuzzerSecurityIssue*` exceptions to allow specifiying the severity of findings

## Version 0.9.0

* Initial release
