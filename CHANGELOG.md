# Changelog

**Note:** Before version 1.0.0, every release may contain breaking changes.

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
