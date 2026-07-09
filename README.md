# Outshake

A minimal, Android-native (Kotlin) Outline-compatible Shadowsocks VPN client for personal use.

## Features
- Import static `ss://` keys (SIP002 and legacy base64 forms).
- Import dynamic `ssconf://` keys — fetches the remote config (JSON, YAML transport graph, or an `ss://` line), with refresh.
- Prefix support in both static (`?prefix=` URL-encoded) and dynamic (JSON/YAML string) flows, applied to the Shadowsocks salt (Outline `PrefixSaltGenerator` semantics).
- Reliable connect/disconnect via Android `VpnService` with a userspace tun2socks (TCP + DNS-over-TCP).
- Real Shadowsocks AEAD transport: `chacha20-ietf-poly1305`, `aes-256-gcm`, `aes-128-gcm`.
- Shake-to-toggle: an accelerometer gesture connects/disconnects the active profile (opt-in, with sensitivity + cooldown).
- Three screens: main (status/profiles), import, settings.

Unsupported ciphers or transport graphs **fail clearly** — nothing is faked.

## Supported key / config matrix
| Input | Supported |
|---|---|
| `ss://base64(method:pass)@host:port#name` (SIP002) | yes |
| `ss://base64(method:pass)@host:port/?prefix=...#name` | yes (prefix) |
| `ss://base64(method:pass@host:port)` (legacy blob) | yes |
| `ssconf://host/path` -> JSON `{server,server_port,password,method,prefix?}` | yes |
| `ssconf://` -> SIP008 `{servers:[...]}` (first server) | yes |
| `ssconf://` -> YAML `transport: {$type: tcpudp, tcp: {$type: shadowsocks,...}}` | yes (TCP branch) |
| `ssconf://` -> body containing an `ss://` line | yes |
| ciphers other than the three AEAD suites above | clear error |
| non-shadowsocks transport `$type` (websocket, tls, ...) | clear error |

## Build
```
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk   # cmdline-tools, platform android-34, build-tools 34.0.0
./gradlew :app:testDebugUnitTest    # parser + crypto unit tests
./gradlew :app:assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
```
minSdk 24, compileSdk/targetSdk 34.

## Install / test
```
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
1. Add profile -> paste an `ss://` or `ssconf://` key -> Import.
2. Tap a profile to make it active, then Connect (grant the VPN permission prompt).
3. Settings -> enable "Shake to connect/disconnect"; shake the device to toggle.

## Known limitations
- Non-DNS UDP is not tunneled (QUIC/HTTP3 falls back to TCP). DNS is forwarded over TCP through the proxy.
- Userspace TCP stack is tuned for the lossless local TUN link (no retransmission/congestion control).
- Shake detection runs while the app is in the foreground.
