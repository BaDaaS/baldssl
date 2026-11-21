#!/usr/bin/env bash
# Builds the os_rng tests for Android (x86_64) against a given API level and,
# with a run level, runs them on an emulator of that API level.
#
# Usage: test-os-rng-android.sh link-fail <build-api>
#        test-os-rng-android.sh run <build-api> <run-api>
#
#   link-fail  linking must fail on an undefined getrandom (an API level
#              below 28, where bionic introduced it)
#   run        build against <build-api>, then run the tests on an emulator
#              with <run-api>: the minimum (28) and a recent level
#
# Needs the Android SDK and NDK of the GitHub Ubuntu runners (ANDROID_HOME,
# ANDROID_NDK_LATEST_HOME) and KVM for the emulator.
set -euo pipefail

usage="usage: test-os-rng-android.sh link-fail <api> | run <api> <run-api>"
mode="${1:?$usage}"
build_api="${2:?$usage}"
target=x86_64-linux-android
root="$(cd "$(dirname "$0")/.." && pwd)"
ndk="${ANDROID_NDK_LATEST_HOME:?the Android NDK is needed}"
linker="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android${build_api}-clang"
[[ -x "$linker" ]] || {
    echo "no NDK clang for API $build_api: $linker" >&2
    exit 1
}

rustup target add "$target"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$linker"
export CARGO_TARGET_DIR="$root/target/android-$build_api"
log="$(mktemp)"
set +e
(cd "$root" && cargo test --locked -p baldssl-crypto --lib --no-run \
    --target "$target") >"$log" 2>&1
status=$?
set -e
cat "$log"

if [[ "$mode" == link-fail ]]; then
    if [[ "$status" -eq 0 ]]; then
        echo "FAIL API $build_api: expected linking to fail below API 28" >&2
        exit 1
    fi
    if ! grep -Eq "undefined (reference to|symbol:) .?getrandom" "$log"; then
        echo "FAIL API $build_api: failed, but not on getrandom" >&2
        exit 1
    fi
    echo "ok API $build_api: linking fails on getrandom, below API 28"
    exit 0
fi

[[ "$mode" == run ]] || {
    echo "$usage" >&2
    exit 2
}
run_api="${3:?$usage}"
if [[ "$status" -ne 0 ]]; then
    echo "FAIL API $build_api: the build failed" >&2
    exit 1
fi
bin="$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$log" |
    head -n 1)"
[[ "$bin" == /* ]] || bin="$root/$bin"

sdk="${ANDROID_HOME:?the Android SDK is needed}"
image="system-images;android-${run_api};default;x86_64"
yes | "$sdk/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true
"$sdk/cmdline-tools/latest/bin/sdkmanager" --install \
    emulator platform-tools "$image" >/dev/null
echo no | "$sdk/cmdline-tools/latest/bin/avdmanager" create avd \
    --force --name os-rng --package "$image" --device pixel_5
adb="$sdk/platform-tools/adb"

"$sdk/emulator/emulator" -avd os-rng -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect >"$root/target/emulator.log" 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT

"$adb" wait-for-device
for _ in $(seq 1 120); do
    if [[ "$("$adb" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; then
        break
    fi
    sleep 5
done
echo "emulator: Android API $("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"

"$adb" push "$bin" /data/local/tmp/os-rng-tests
"$adb" shell chmod 755 /data/local/tmp/os-rng-tests
# adb shell returns the remote exit status (Android 7 and later).
"$adb" shell /data/local/tmp/os-rng-tests os_rng
echo "ok: built for API $build_api, os_rng tests pass on API $run_api"
