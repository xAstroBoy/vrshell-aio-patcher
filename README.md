# vrshell-aio-patcher — all-in-one patched Quest VrShell

Companion device patcher for **[Quest-Home-Editor](https://github.com/xAstroBoy/Quest-Home-Editor)**. Every
Quest `VrShell` hook / tool is compiled into **one** `libquestctl_aio.so`, baked into libshell's existing
`DT_NEEDED` slot (libshell itself is left byte-for-byte untouched) and hot-swapped in via a Magisk overlay —
no reboot, no re-signing of libshell. It exposes a tiny TCP control server on `127.0.0.1:27042` (reachable
over `adb forward`) that the desktop editor and the MCP tools drive live.

> ⚠️ **This repo contains source only.** It patches Meta's proprietary `VrShell.apk` (which embeds
> `libshell.so`). **Neither the stock nor the patched APK is redistributed here** — you build your own from the
> `VrShell.apk` already on *your* headset (`scripts/build_and_deploy.sh` pulls it). Nothing in `.gitignore`'d
> `work/`, `dist/`, or the `*.apk` files leaves your machine.

## Features (all opt-in via `hsr.*` system props / the bridge)
| feature | what | control |
|---|---|---|
| **far-clip** | extend the 5000 m PortalStereoCamera far plane so distant/cooked geometry isn't clipped | `hsr.farclip` |
| **moonjump / fly** | hold Jump = rise (hooks `PhysxCharacterController::move` right after gravity, writes the vertical-velocity accumulator) | `hsr.moonjump` / `hsr.fly` |
| **no-gravity** | zero the vertical velocity every frame so the player never falls / resets after a teleport | `hsr.nogravity`, bridge `nogravity 0\|1` |
| **teleport / rotate / walk** | post the game's own teleport message (respects collision, sets facing yaw) | bridge `warp x y z [yaw]` / `rot yaw`, `hsr.tp`/`hsr.rot`/`hsr.walk` |
| **player readback** | live feet + head position + head-forward heading + no-gravity state | bridge `playerpos` |
| **crashproof** | try/catch around asset-init so one bad cooked mesh can't take down the shell | `hsr.crashproof` |
| **world-time** | freeze / slow / scrub the entire animation clock (desktop timeline mirror) | bridge `world <speed>` / `world setphase` / `world settime` |
| **dumper** | on-device renderable / cull / skeleton / material dump | bridge `renderables`, `envdump`, `meshmat`, … |

## Bridge protocol
Newline-delimited commands over a **persistent** TCP connection on `127.0.0.1:27042` (one connection can stream
many commands — the editor keeps it open for smooth live control; one-shot clients also work). Examples:
```
printf 'nogravity 1\nwarp 0 8 0\nplayerpos\n' | nc 127.0.0.1 27042
# -> OK nogravity ON ...
# -> OK warp -> 0.00,8.00,0.00 yaw 0.000
# -> head=.. face=<deg> feet=0.000,8.000,0.000 nograv=1 (aio)
```
`questctl` (a Magisk `system/bin` shim) wraps the same via props for the MCP: `questctl nogravity 1`,
`questctl teleport X Y Z [yaw]`, `questctl rotate YAW`, `questctl status`, …

## Layout
```
src/
  common/     hookutil.h (pattern-scan / ADRP-resolve / trampoline-install / arm64 encoders / feat_report),
              zygisk.hpp (the standard Zygisk module API header)
  features/   aio.cpp        far-clip / moonjump / fly / no-gravity / teleport / crashproof
              rendertrace.cpp on-device dumper + the 127.0.0.1:27042 control server
              player.cpp     walk / rotate / pos (standalone Zygisk variant)
              unlock.cpp     unlock built-in hidden menus
  core/       orchestrator.cpp  the ONE constructor that spawns every feature worker (a single ctor avoids the
                                init-array GC that used to drop one feature in the merged build)
  merge/      *_tu.cpp       thin wrappers so each feature TU links into the one libquestctl_aio.so
build/        Android.mk  Application.mk        (ndk-build)
scripts/      build_aio.py (LIEF: add the DT_NEEDED) · replace_lib.py (swap the .so into the apk) · build_and_deploy.sh
module/       service.sh (launch-first bind + arm props) · post-fs-data.sh · system/bin/questctl
mcp/          quest_ctl_mcp.py · hsr_world_mcp.py   (Claude MCP: runtime inspect + control)
```

## Build + deploy
```bash
scripts/build_and_deploy.sh     # ndk-build the .so, swap it into YOUR VrShell.apk, sign, hot-swap, restart
```
Requires: Android NDK (`ndk-build`), Android build-tools (`zipalign` + `apksigner`), a **rooted** Quest with
Magisk, and `adb`. The deploy binds the patched apk over `/system_ext/priv-app/VrShell/VrShell.apk` inside PID 1's
mount namespace (`nsenter`) so it survives without a reboot; `module/service.sh` re-applies it at boot (launch-first
so PMS keeps the platform signature/permissions).

⚠️ Notes learned the hard way: use **PowerShell** for `adb push` on Windows (MSYS mangles `/sdcard`); patch the
`.so` inside the apk (never LIEF-rewrite the ~43 MB `libshell.so` a second time — it corrupts it); a re-signed
`VrShell.apk` loses the `signature|knownSigner` `READ_SETTINGS` permission, which is why the boot bind happens
*after* PMS has scanned the stock apk.

## Design
- **One `.so`, libshell untouched.** We only replace `libquestctl_aio.so` inside the apk; libshell's DT_NEEDED
  already points at it. This is why moonjump/far-clip never corrupt the shell.
- **One worker installs everything and reports per-feature** via `feat_report(name, ok, detail)` → the `stat`
  bridge command shows exactly which hook armed or failed, instead of guessing.
- **Opt-in + recoverable**: every feature is a prop, default-safe; a bad hook is recovered by flipping the prop
  and reloading the shell — no reboot, disk untouched.

Not affiliated with Meta. For research/personal use on hardware you own.
