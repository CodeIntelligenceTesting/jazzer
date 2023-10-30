"""Repository rule for Android SKD and NDK autoconfigure"""

_ANDROID_SDK_HOME = "ANDROID_HOME"
_ANDROID_NDK_HOME = "ANDROID_NDK_HOME"

_ANDROID_REPOS_TEMPLATE = """android_sdk_repository(
        name="androidsdk",
        path={sdk_home},
    )
    android_ndk_repository(
        name="androidndk",
        path={ndk_home},
    )
"""

def _is_windows(repository_ctx):
    """Returns true if the current platform is Windows"""
    return repository_ctx.os.name.lower().startswith("windows")

def _supports_android(repository_ctx):
    sdk_home = repository_ctx.os.environ.get(_ANDROID_SDK_HOME)
    ndk_home = repository_ctx.os.environ.get(_ANDROID_NDK_HOME)
    return sdk_home and ndk_home and not _is_windows(repository_ctx)

def _android_autoconf_impl(repository_ctx):
    """Implementation of the android_autoconf repo rule"""
    sdk_home = repository_ctx.os.environ.get(_ANDROID_SDK_HOME)
    ndk_home = repository_ctx.os.environ.get(_ANDROID_NDK_HOME)

    # rules_android_ndk does not support Windows yet.
    if _supports_android(repository_ctx):
        repos = _ANDROID_REPOS_TEMPLATE.format(
            sdk_home = repr(sdk_home),
            ndk_home = repr(ndk_home),
        )
    else:
        repos = "pass"

    repository_ctx.file("BUILD.bazel", "")
    repository_ctx.file("android_configure.bzl", """
load("@rules_android//android:rules.bzl", "android_sdk_repository")
load("@rules_android_ndk//:rules.bzl", "android_ndk_repository")

def android_workspace():
    {repos}
    """.format(repos = repos))

android_configure = repository_rule(
    implementation = _android_autoconf_impl,
    environ = [
        _ANDROID_SDK_HOME,
        _ANDROID_NDK_HOME,
    ],
)
