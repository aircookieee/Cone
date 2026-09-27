"""Observe Our Notes metadata file reads on the native ARM device."""

import sys
import time
from pathlib import Path

import frida


DEVICE_ID = sys.argv[1] if len(sys.argv) > 1 else "YOUR_ADB_SERIAL"
PACKAGE = "com.bilibili.sirius"

JS = r"""
const fds = new Set();
let scanCount = 0;
let dumped = false;
function scanMetadata() {
  if (dumped) return;
  scanCount++;
  const pattern = 'f4 9b 02 00 24 9c 02 00 58 9c 02 00 8c 9c 02 00';
  let searched = 0, hits = 0;
  for (const range of Process.enumerateRanges({protection:'r--', coalesce:true})) {
    if (range.size < 0x6000 || range.size > 0x10000000) continue;
    searched++;
    try {
      for (const hit of Memory.scanSync(range.base, range.size, pattern)) {
        hits++;
        const base = hit.address.sub(0x5000);
        if (base.compare(range.base) < 0) continue;
        const span = base.add(0x1000).readByteArray(0x4000);
        send({kind:'candidate', scan:scanCount, base:String(base), range:String(range.base), size:range.size}, span);
        if (!dumped && base.compare(range.base) === 0 && range.size >= 31547372) {
          dumped = true;
          const length = 31547372, chunkSize = 1024 * 1024;
          const count = Math.ceil(length / chunkSize);
          for (let i = 0; i < count; i++) {
            const offset = i * chunkSize;
            send({kind:'chunk', index:i, count:count}, base.add(offset).readByteArray(Math.min(chunkSize, length - offset)));
          }
          send({kind:'dump-done', chunks:count});
          return;
        }
      }
    } catch (e) { send({kind:'scan-error', error:String(e)}); }
  }
  send({kind:'scan-done', scan:scanCount, searched:searched, hits:hits});
}
function hook(name, enter, leave) {
  try {
    const address = DebugSymbol.getFunctionByName(name);
    if (address === null) return;
    Interceptor.attach(address, { onEnter: enter, onLeave: leave });
    send({kind: 'hook', name: name, address: String(address)});
  } catch (e) { send({kind: 'hook-error', name: name, error: String(e)}); }
}
function checkPath(path) { return path.indexOf('global-metadata.dat') >= 0; }
hook('openat', function(args) {
  try { this.target = checkPath(args[1].readCString()); }
  catch (e) { this.target = false; }
}, function(ret) {
  if (this.target) { fds.add(ret.toInt32()); send({kind:'openat', fd:ret.toInt32()}); }
});
hook('open', function(args) {
  try { this.target = checkPath(args[0].readCString()); }
  catch (e) { this.target = false; }
}, function(ret) {
  if (this.target) { fds.add(ret.toInt32()); send({kind:'open', fd:ret.toInt32()}); }
});
hook('read', function(args) {
  this.fd=args[0].toInt32(); this.buf=args[1]; this.want=args[2].toInt32();
}, function(ret) {
  if (fds.has(this.fd)) send({kind:'read', fd:this.fd, buffer:String(this.buf), want:this.want, got:ret.toInt32()});
});
hook('pread64', function(args) {
  this.fd=args[0].toInt32(); this.buf=args[1]; this.want=args[2].toInt32(); this.offset=String(args[3]);
}, function(ret) {
  if (fds.has(this.fd)) send({kind:'pread64', fd:this.fd, buffer:String(this.buf), want:this.want, got:ret.toInt32(), offset:this.offset});
});
hook('mmap', function(args) {
  this.fd=args[4].toInt32(); this.length=String(args[1]); this.offset=String(args[5]);
}, function(ret) {
  if (fds.has(this.fd)) send({kind:'mmap', fd:this.fd, address:String(ret), length:this.length, offset:this.offset});
});
hook('close', function(args) { this.fd=args[0].toInt32(); }, function(ret) {
  if (fds.delete(this.fd)) {
    send({kind:'close', fd:this.fd});
    setTimeout(scanMetadata, 100);
    setTimeout(scanMetadata, 800);
    setTimeout(scanMetadata, 1800);
  }
});
"""


def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload.get("kind") == "chunk":
            chunks[payload["index"]] = data
            if len(chunks) == payload["count"]:
                out = Path("analysis/il2cpp/global-metadata-runtime-raw.dat")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"".join(chunks[i] for i in range(payload["count"])))
                print(f"saved {out} ({out.stat().st_size} bytes)", flush=True)
        elif payload.get("kind") != "candidate":
            print(payload, flush=True)
    else:
        print(message, flush=True)


device = frida.get_device_matching(lambda d: d.id == DEVICE_ID, timeout=10)
chunks = {}
pid = device.spawn(PACKAGE)
session = device.attach(pid)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
device.resume(pid)
print(f"resumed pid={pid}", flush=True)
time.sleep(10)
try:
    session.detach()
except frida.InvalidOperationError:
    pass
