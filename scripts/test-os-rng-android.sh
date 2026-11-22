#!/usr/bin/env bash
# Builds the os_rng tests for Android (x86_64) against a given API level and,
# with a run level, runs them on an emulator of that API level.
#
# Usage: test-os-rng-android.sh link-fail <build-api>
#        test-os-rng-android.sh run <build-api> <run-api>
#
#   link-fail  linking must fail on an undefined getrandom (an API level
#              below 28, Android 9, where bionic, Android's libc,
#              introduced it)
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
# The binary's path is read from cargo's output, which must be plain text
# (CI sets CARGO_TERM_COLOR=always).
export CARGO_TERM_COLOR=never
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
[[ -f "$bin" ]] || {
    echo "FAIL: no test binary found in cargo's output (got '$bin')" >&2
    exit 1
}

sdk="${ANDROID_HOME:?the Android SDK is needed}"
image="system-images;android-${run_api};default;x86_64"
yes | "$sdk/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true
"$sdk/cmdline-tools/latest/bin/sdkmanager" --install \
    emulator platform-tools "$image"
# One directory for the virtual device, for both tools: recent avdmanager
# and the emulator do not default to the same one (the emulator reported
# "Unknown AVD name" for a device avdmanager had just created). The emulator
# searches ANDROID_AVD_HOME first.
export ANDROID_USER_HOME="$root/target/android-user"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
echo no | "$sdk/cmdline-tools/latest/bin/avdmanager" create avd \
    --force --name os-rng --package "$image" --device pixel_5
adb="$sdk/platform-tools/adb"
log="$root/target/emulator.log"
if ! "$sdk/emulator/emulator" -list-avds | grep -qx os-rng; then
    echo "FAIL: the emulator does not see the device avdmanager created" >&2
    "$sdk/emulator/emulator" -list-avds >&2 || true
    ls -la "$ANDROID_AVD_HOME" >&2 || true
    exit 1
fi

# Every wait below is bounded, and a failure prints the emulator's own log:
# an emulator that dies at start-up otherwise leaves `adb wait-for-device`
# blocked until the job times out, with nothing in the output.
fail() {
    echo "FAIL: $1" >&2
    echo "--- emulator log (last 80 lines) ---" >&2
    tail -n 80 "$log" >&2 || true
    exit 1
}
"$sdk/emulator/emulator" -accel-check || true
"$sdk/emulator/emulator" -avd os-rng -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect >"$log" 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT

booted=0
for _ in $(seq 1 120); do
    kill -0 "$emulator_pid" 2>/dev/null || fail "the emulator exited"
    state="$(timeout 10 "$adb" shell getprop sys.boot_completed 2>/dev/null |
        tr -d '\r' || true)"
    if [[ "$state" == 1 ]]; then
        booted=1
        break
    fi
    sleep 5
done
[[ "$booted" == 1 ]] || fail "the emulator did not boot in 10 minutes"
echo "emulator: Android API $(timeout 30 "$adb" shell getprop \
    ro.build.version.sdk | tr -d '\r')"

timeout 120 "$adb" push "$bin" /data/local/tmp/os-rng-tests ||
    fail "adb push"
timeout 60 "$adb" shell chmod 755 /data/local/tmp/os-rng-tests ||
    fail "adb shell chmod"
# adb shell returns the remote exit status (Android 7 and later).
timeout 600 "$adb" shell /data/local/tmp/os-rng-tests os_rng ||
    fail "the os_rng tests failed or timed out"
echo "ok: built for API $build_api, os_rng tests pass on API $run_api"
