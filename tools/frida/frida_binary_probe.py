"""Compare selected loaded libil2cpp pages with the original ELF on a native ARM device."""

import json
import sys
import time
from pathlib import Path

import frida


DEVICE_ID = sys.argv[1] if len(sys.argv) > 1 else "YOUR_ADB_SERIAL"
PACKAGE = "com.bilibili.sirius"
SOURCE = Path(
    "BanG+Dream!+Our+Notes_1.0.1_APKPure/config.arm64_v8a/lib/arm64-v8a/libil2cpp.so"
)
REPAIRED = Path("analysis/il2cpp/libil2cpp-deobfuscated.so")
SAMPLES = [
    ("rodata_first_mask", 0x1FFC000, 0x1FFC000, 0x4000),
    ("generic_masked", 0x26EC000, 0x26EC000, 0x1000),
    ("generic_plain", 0x26F0000, 0x26F0000, 0x1000),
    ("rodata_late_mask", 0x2D2C000, 0x2D2C000, 0x1000),
    ("rodata_tail", 0x2D30000, 0x2D30000, 0x17D4),
    ("text_raw_c000", 0x4D8C000, 0x4D90000, 0x1000),
    ("il2cpp_first_mask", 0x54CC000, 0x54D0000, 0x4000),
    ("il2cpp_first_plain", 0x54D0000, 0x54D4000, 0x1000),
    ("il2cpp_raw_c000", 0x54DC000, 0x54E0000, 0x1000),
    ("il2cpp_middle_mask", 0x800C000, 0x8010000, 0x1000),
    ("il2cpp_late_mask", 0xBDDC000, 0xBDE0000, 0x1000),
    ("il2cpp_tail", 0xBDE0000, 0xBDE4000, 0xA434),
]

JS = """
const samples = %s;
let seen = false, pass = 0;
const timer = setInterval(function () {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (mod === null) return;
    if (!seen) { seen = true; send({kind:'module', base:String(mod.base), size:mod.size}); }
    pass++;
    for (const [name, raw, va, length] of samples) {
        try { send({kind:'sample', pass:pass, name:name}, mod.base.add(va).readByteArray(length)); }
        catch (e) { send({kind:'error', pass:pass, name:name, error:String(e)}); }
    }
    if (pass >= 1) clearInterval(timer);
}, 300);
""" % (json.dumps(SAMPLES),)


def main() -> None:
    source = SOURCE.read_bytes()
    repaired = REPAIRED.read_bytes() if REPAIRED.exists() else None

    def on_message(message, data):
        if message["type"] != "send":
            print(message, flush=True)
            return
        msg = message["payload"]
        if msg.get("kind") != "sample":
            print(msg, flush=True)
            return
        name = msg["name"]
        raw = next(offset for label, offset, _, _ in SAMPLES if label == name)
        disk = source[raw : raw + len(data)]
        same = sum(a == b for a, b in zip(data, disk))
        xor98 = sum((a ^ b) == 0x98 for a, b in zip(data, disk))
        other = len(data) - same - xor98
        repaired_same = (
            sum(a == b for a, b in zip(data, repaired[raw:raw + len(data)]))
            if repaired is not None else None
        )
        print(
            f"pass={msg['pass']} {name}: same={same} xor98={xor98} other={other} "
            f"repaired_same={repaired_same} disk={disk[:16].hex()} mem={data[:16].hex()}",
            flush=True,
        )
        if name in ("rodata_first_mask", "il2cpp_first_mask"):
            out = Path("analysis/il2cpp") / f"{name}-runtime.bin"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            print(f"saved {out} ({len(data)} bytes)", flush=True)

    device = frida.get_device_matching(lambda d: d.id == DEVICE_ID, timeout=10)
    pid = device.spawn(PACKAGE)
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    print(f"resumed pid={pid}", flush=True)
    time.sleep(4)
    try:
        session.detach()
    except frida.InvalidOperationError:
        pass


if __name__ == "__main__":
    main()
