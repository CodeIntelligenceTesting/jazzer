#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#
# This file also contains code licensed under Apache2 license.
#

_sanitizer_package_prefix = "com.code_intelligence.jazzer.sanitizers."

_sanitizer_class_names = [
    # keep sorted
    "ClojureLangHooks",
    "Deserialization",
    "ExpressionLanguageInjection",
    "LdapInjection",
    "NamingContextLookup",
    "OsCommandInjection",
    "ReflectiveCall",
    "RegexInjection",
    "RegexRoadblocks",
    "ScriptEngineInjection",
    "ServerSideRequestForgery",
    "SqlInjection",
    "XPathInjection",
]

SANITIZER_CLASSES = [_sanitizer_package_prefix + class_name for class_name in _sanitizer_class_names]
