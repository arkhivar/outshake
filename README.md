# Outshake

A minimal, Android-native (Kotlin) Outline-compatible Shadowsocks VPN client for personal use.

## Features
- Import static `ss://` keys (SIP002 and legacy base64 forms).
- Import dynamic `ssconf://` keys — fetches the remote config (JSON, YAML transport graph, or an `ss://` line), with refresh.
- Prefix support in both static (`?prefix=` URL-encoded) and dynamic (JSON/YAML string) flows, applied to the Shadowsocks salt (Outline `PrefixSaltGenerator` semantics).
- Reliable connect/disconnect via Android `VpnService` with a userspace tun2socks (full TCP + UDP relay).
- Full Shadowsocks UDP relay (SIP007): QUIC/HTTP3, games and voice tunnel over UDP with a per-flow NAT table and idle eviction. DNS is sent over UDP with an automatic DNS-over-TCP fallback for servers that have UDP disabled.
- "Install and forget" reliability: auto-reconnect on Wi-Fi↔cellular changes, process-death recovery (the tunnel comes back after a memory kill), an optional connect-on-boot toggle (off by default), and a one-shot config re-fetch + retry when a dynamic (ssconf) profile fails to connect.
- Real Shadowsocks AEAD transport: `chacha20-ietf-poly1305`, `aes-256-gcm`, `aes-128-gcm`.
- Shake-to-toggle: an accelerometer gesture connects/disconnects the active profile (on by default, with sensitivity + a ~5s cooldown). Runs in a small foreground service so it works while the app is backgrounded; a quiet shaker sound (brighter = on, darker = off) plus an on-screen "VPN activated"/"VPN off" toast fire the instant a shake is accepted. The sound uses the notification stream, so it stays silent when the ringer is on silent/vibrate.
- Quick Settings tile: tap to toggle the active profile (same logic as the shake gesture, via the shared `ConnectionManager`); the tile shows Active/Inactive/Unavailable from live connection state.
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
- The Outline "prefix" is applied to the TCP salt only (matching Outline's `PrefixSaltGenerator`); UDP datagrams use a fully random salt per packet, as the spec/Outline intend.
- Userspace TCP stack is tuned for the lossless local TUN link (no retransmission/congestion control).
- Background shake and auto-reconnect are best-effort during deep doze with the screen off (no wakelock, battery-sane).
