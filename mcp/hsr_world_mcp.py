#!/usr/bin/env python3
"""
hsr-world  --  MCP bridge to the ON-DEVICE libshell render world
=================================================================
Talks to the `librendertrace.so` control server (injected into vrshell as a DT_NEEDED
of libshell, delivered via the overlay-bound patched VrShell.apk). Lets Claude inspect
and CONTROL the live render world on the Quest: dump the per-renderable cull verdicts
(VISIBLE / DIST-CULL / FRUSTUM-CULL / NOCULL), dump skeletons, and read/write arbitrary
runtime values (base-relative `+offset` or absolute) — to find why animated/skinned
meshes disappear or land wrong, and to tweak culling/bounds/values live.

Transport: stdio. Deps: adb on PATH; `pip install mcp`.
The device side is `_zygisk_rendertrace/module.cpp` (control_server, port 27042).
"""
import os, socket, subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hsr-world")

SERIAL = os.environ.get("QUEST_SERIAL", "2G0YC5ZG5P09DS")
PORT   = int(os.environ.get("HSR_RT_PORT", "27042"))

def _adb(args, timeout=30):
    try:
        r = subprocess.run(["adb", "-s", SERIAL] + args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr.strip() else "")
    except Exception as e:
        return "[adb error] " + str(e)

def _forward():
    """Ensure `adb forward tcp:PORT tcp:PORT` is live so we can reach the device control server."""
    _adb(["forward", f"tcp:{PORT}", f"tcp:{PORT}"])

def _send(cmd: str, timeout: float = 5.0) -> str:
    """One command per connection: send 'cmd\\n', half-close write, read all until EOF."""
    _forward()
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    except Exception as e:
        return (f"[connect failed: {e}]  The device control server may be down. "
                f"Check: vrshell running with the patched apk, `setprop hsr.rt_mcp 1`, "
                f"and `logcat -s HSR-RT` shows 'MCP control server LIVE'.")
    try:
        # NOTE: do NOT shutdown(SHUT_WR) — adb-forward turns the half-close into a full close
        # and truncates the request. The device server reads one '\n'-terminated line then
        # closes the connection itself, so we just send and read until EOF.
        s.sendall((cmd.strip() + "\n").encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            buf += chunk
        return buf.decode("utf-8", "replace")
    except Exception as e:
        return f"[io error: {e}]"
    finally:
        s.close()

@mcp.tool()
def hsr_world_connect() -> str:
    """Set up adb port-forward to the device render-world control server and ping it.
    Run this first. Returns 'pong base=0x...' with the live libshell base address."""
    _adb(["connect", SERIAL]) if ":" in SERIAL else None
    return _send("ping")

@mcp.tool()
def hsr_world_base() -> str:
    """Return the live libshell load base (for computing +offset addresses)."""
    return _send("base")

@mcp.tool()
def hsr_renderables() -> str:
    """Dump the live cull world: one line per renderable with its bounding center (cx,cy,cz),
    half-extents (ex,ey,ez), the exact cull VERDICT (VISIBLE / DIST-CULL / FRUSTUM-CULL /
    NOCULL / BADBOUNDS) and proxy address. Header has camera pos, far-clip threshold (m),
    and frustum count. THIS is the tool for 'why did the mesh disappear': rotate the mesh,
    re-run, and watch which proxy flips to FRUSTUM-CULL (and whether its center/ext is wrong)."""
    return _send("renderables")

@mcp.tool()
def hsr_skeletons() -> str:
    """Dump live skeletons (SkeletonSystem_vf7): per skeleton, self ptr, joint count, and
    whether its cull bounds were rebuilt this frame. Only populated once a skinned env loads."""
    return _send("skeletons")

@mcp.tool()
def hsr_read(addr: str, length: int = 16) -> str:
    """Read raw bytes from the live process. addr = '+1480F70' (libshell base-relative, preferred)
    or '0x...' absolute. Safe (process_vm_readv): a bad address returns ERR EFAULT, never crashes."""
    return _send(f"read {addr} {length}")

@mcp.tool()
def hsr_write(addr: str, hexbytes: str) -> str:
    """Write raw bytes (hex, e.g. '0000803f') to the live process. addr = '+offset' or '0x...'.
    Flips the page writable first; safe-faults. Use to tweak runtime values / patch live."""
    return _send(f"write {addr} {hexbytes}")

@mcp.tool()
def hsr_read_f32(addr: str) -> str:
    """Read a 32-bit float at addr ('+offset' or '0x...')."""
    return _send(f"rf32 {addr}")

@mcp.tool()
def hsr_write_f32(addr: str, value: float) -> str:
    """Write a 32-bit float at addr ('+offset' or '0x...'). Live runtime-value tweak."""
    return _send(f"wf32 {addr} {value}")

@mcp.tool()
def hsr_read_u32(addr: str) -> str:
    """Read a 32-bit unsigned int at addr ('+offset' or '0x...')."""
    return _send(f"r32 {addr}")

@mcp.tool()
def hsr_write_u32(addr: str, value: int) -> str:
    """Write a 32-bit unsigned int at addr ('+offset' or '0x...'). Live runtime-value tweak."""
    return _send(f"w32 {addr} {value}")

@mcp.tool()
def hsr_player_pos() -> str:
    """Read the live PLAYER position (and nearby floats to locate rotation/quaternion), from the
    stashed SlideLocomotionController (a3+144). Move/turn in-headset once first so the controller
    is captured. Returns 'pos=x,y,z  +12..28=...' — correlate pos with the cull camera pos."""
    return _send("playerpos")

@mcp.tool()
def hsr_player_setpos(x: float, y: float, z: float) -> str:
    """Write the player position directly (a3+144). NOTE: the physics character controller may
    re-assert position next frame, so this may not 'stick' — use for probing / teleport attempts."""
    return _send(f"setpos {x} {y} {z}")

@mcp.tool()
def hsr_player_move(dx: float, dy: float, dz: float) -> str:
    """Add a delta to the player position (a3+144). Same physics caveat as setpos."""
    return _send(f"move {dx} {dy} {dz}")

@mcp.tool()
def hsr_loadenv(env: str) -> str:
    """LIVE-swap the environment with NO vrshell restart (keeps the MCP server alive!).
    Sets `environment_selected` via oculuspreferences, which fires the in-process
    EnvironmentSystem::setCurrentEnvironment callback → loads any recognized env live
    (Footprint/Vista/Environment), cooked envs included. `env` = a package name or an alias:
    incredibles | nuxd | haven2025 | calming. DO NOT kill vrshell — that drops the companion."""
    alias = {
        "incredibles": "com.environment.incredibles",
        "nuxd": "com.meta.environment.prod.nuxd",
        "haven2025": "com.meta.shell.env.footprint.haven2025",
        "calming": "com.meta.shell.env.vista.calming",
    }
    pkg = alias.get(env.strip().lower(), env.strip())
    uri = f"apk://{pkg}/assets/scene.zip"
    _adb(["shell", "logcat", "-c"])
    out = _adb(["shell", "oculuspreferences", "--setc", "environment_selected", uri])
    import time; time.sleep(4)
    log = _adb(["shell",
        "logcat -d 2>/dev/null | grep -iE 'Scene loaded|as Environment|as Footprint|as Vista|not valid|resetting' | tail -3"])
    return f"set {uri}\n{out.strip()}\n--- EnvironmentSystem ---\n{log.strip()}"

@mcp.tool()
def hsr_loco() -> str:
    """Dump the stashed locomotion controller pointers (this, a3) + the pos offset — for live
    offset-finding (read floats around them with hsr_read to pin rotation/velocity fields)."""
    return _send("loco")

@mcp.tool()
def hsr_log(which: str, on: bool) -> str:
    """Toggle the logcat trace live (no reinstall). which = 'cull' or 'skel'. Then `adb logcat -s HSR-RT`."""
    return _send(f"log {which} {1 if on else 0}")

@mcp.tool()
def hsr_raw(command: str) -> str:
    """Send a raw command to the device control server (escape hatch). Commands:
    ping | base | renderables | skeletons | read ADDR LEN | write ADDR HEX |
    r32/rf32 ADDR | w32/wf32 ADDR VAL | log cull|skel 0|1 | loglevel N."""
    return _send(command)

if __name__ == "__main__":
    mcp.run()
