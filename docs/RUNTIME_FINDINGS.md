# Runtime findings for Our Notes 1.0.1

The unmodified Android package was observed on rooted BlueStacks Rvc64 (Android 11, x86_64 with ARM translation) and a native arm64 Poco F3 (Android 13). These observations supplement the [static findings](FINDINGS.md). Raw captures and logs stay under the ignored `analysis/runtime-logs/` directory.

## Devices and observed behavior

| Device | Result |
|---|---|
| BlueStacks Rvc64 | Game reaches a Bilibili sign-in dialog. No account sign-in was performed. |
| Poco F3 | Game exits within seconds on every tested launch, usually recorded as SIGBUS (7), once as SIGSEGV (11). |
| Android 7.1.2 armeabi-v7a device | Below the package's minimum SDK 26 and lacks arm64; unusable for this build. |

The Poco failures persisted after clearing app data, disabling network, hiding the Magisk app, and stopping frida-server. The installed split APKs matched the supplied package hashes recorded in [FINDINGS.md](FINDINGS.md). Those comparisons narrow the cause, but do not identify it. The game reached Unity initialization and sometimes the first activity draw. No clean-run game fault stack was recovered.

BlueStacks runs the ARM game through `libnb.so`. Frida 17.14.1 attached to its x86_64 process and enumerated system/native-bridge modules, but could not see translated `libil2cpp.so` or Unity. Native IL2CPP hooks therefore need a native arm64 target.

For the BlueStacks session, system ADB connected to the Rvc64 instance at `127.0.0.1:5555` after root and reboot; it had previously used port 5556. The x86_64 Frida server was started with root UID and reached through `adb forward tcp:27042 tcp:27042` and `frida-ps -H 127.0.0.1`. The ARM Frida server could not run directly in the emulator shell. These setup details explain the scope of the module observations; they are not needed for static metadata recovery.

## Poco signal investigation

Several early probes used `Module.getExportByName` / `Module.findExportByName`, APIs unavailable in the tested Frida 17 environment. Their catch blocks hid the lookup failures, so those runs provide no negative evidence about hooked calls. The retained [signal watch](../tools/frida/frida_signal_watch.py) uses `DebugSymbol.getFunctionByName` and FUZZY backtraces. It saw repeated `tgkill` calls with SIGXCPU (24) and SIGPWR (30), attributed only as far as `libc.so`; see `analysis/runtime-logs/watch6.log`. It did not see `kill`, `abort`, `exit`, `_exit`, or `ptrace` calls before death. File hooks saw one `/proc/self/maps` open but no observed `/proc/self/status`, `su`, `magisk`, `xposed`, or `busybox` probe. These are observations of hooked paths, not proof that no other checks occur.

The first signal script misread arm64 bionic's `struct sigaction`: `0x18000004` was `sa_flags` at offset 0, not a handler pointer. The [corrected layout probe](../tools/frida/frida_sig_layout.py) reads the pointer at offset 8. It recorded Unity registering the same handler, `libunity.so + 0xa9dbd8`, for signals 6, 7, and 11 with flags `0x18000004`. The [handler probe](../tools/frida/frida_unity_crash_probe.py) then observed the registrations and two further SIGBUS process exits, but no entry into that handler. Its 100 ms disposition samples saw no later change. Logs: `analysis/runtime-logs/sig-layout-20260927.jsonl`, `unity-crash-probe-20260927.jsonl`, and `unity-crash-probe-sampled-20260927.jsonl`. A separate tombstone for PID 11987 points to a Frida-agent null dereference and does not identify the game's underlying fault.

An earlier kernel ftrace window captured no game `signal_generate` / `signal_deliver` event during a clean exit. That negative result needs a controlled-signal validation before it can support a causal claim. Frida interception in a signal handler can also miss events. The observed Unity disposition does not prove that Unity consumed the fatal signal, nor does it establish that Frida's handler was replaced.

## BlueStacks startup traffic

A 50-second, emulator-wide `tcpdump -i any -s 0` capture during launch contained 1,486 packets with no reported kernel drops. The local PCAP is `analysis/runtime-logs/ournotes-bluestacks-startup-20260927.pcap` (SHA-256 `20726156998d4b8c264ff5030f28d302121e2d3853dc0c2934f46de0e69c9000`). It is kept outside Git because payloads can contain identifiers. [summarize_tls_capture.py](../tools/frida/summarize_tls_capture.py) generated the local ClientHello summary at `analysis/runtime-logs/ournotes-bluestacks-startup-20260927-tls.tsv`.

| SNI observed | Offered ALPN | Attribution |
|---|---|---|
| `config.uca.cloud.unity3d.com`, `cdp.cloud.unity3d.com` | `h2,http/1.1` | Later socket snapshot tied both to the game PID. |
| `l11-sdk-login-intl.biligame.net`, `log-collect-intl.biligame.net` | `h2,http/1.1` | Bilibili SDK candidates; short-lived game sockets were seen live but that socket snapshot was not retained. |
| `oversea-sdk-hot-deploy.biligame.net`, `l11-sdk-api-intl.biligame.net`, `l1-game-support-intl.biligame.net`, `cloud-storage-intl.biligame.net`, `l11-game-support-intl.biligame.net`, `bilibiligame.aihelp.net` | Mostly `h2,http/1.1` | Bilibili SDK/support candidates. |
| `a3wyav.cdn-settings.appsflyersdk.com` | `http/1.1` | AppsFlyer candidate. |

Other captured hosts included `dl.listdl.com` and Google Ads endpoints. The emulator-wide capture alone cannot attribute every connection to the game. The saved socket snapshot is `analysis/runtime-logs/ournotes-bluestacks-sockets-20260927.txt`. Neither `api.bang-dream-on.jp` nor `l14-prod-hk-all-gs-sirius.gamerfusiontech.com` appeared in this pre-login window. The ALPN values are client offers, not negotiated protocol evidence. TLS prevents this capture from showing HTTP paths, gRPC calls, request metadata, or responses. No Our Notes backend exchange was confirmed.

## Integrity checks and limits

Recovered metadata contains `DeviceIntegrityValidationGate.ValidateIfNeeded`, `PlayIntegrity.Validate`, `DeviceIntegrityApi.Validate`, `LocalPermanentData.IsDeviceIntegrityValidatedWithin`, and the `IntegrityService.IntegrityCheck` RPC. Its request has a token string. The response includes `RequestDetails`, `AppIntegrity`, `DeviceIntegrity`, and `AccountDetails`; recognition verdict fields are strings, not numeric enums. The Poco's `ano_tmp` files include small `ace_*` and `tersafe` blobs consistent with Tencent ACE components. These are static or on-device indicators, not a captured integrity verdict or proof of why the game exits. Repackaging impact and the gate's exact control flow remain unmeasured.

Next useful evidence is an authorized post-login capture to identify actual backend hosts and calls, and a native Poco fault trace validated against a known signal. The existing PCAP cannot decrypt TLS or establish server behavior.
