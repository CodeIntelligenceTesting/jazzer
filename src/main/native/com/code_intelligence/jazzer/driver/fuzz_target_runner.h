// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#pragma once

namespace jazzer {
/*
 * Print the stack traces of all active JVM threads.
 *
 * This function can be called from any thread.
 */
void DumpJvmStackTraces();
}  // namespace jazzer
