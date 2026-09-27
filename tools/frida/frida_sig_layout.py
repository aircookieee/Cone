"""Observe arm64 bionic sigaction installs during an Our Notes spawn.

Bionic LP64 struct sigaction starts with int sa_flags at offset 0 and has
the function pointer at offset 8. Earlier observations mistakenly labeled
sa_flags as the handler.
"""

import argparse
import json
import time
from pathlib import Path

import frida


PKG = "com.bilibili.sirius"
JS = r"""
function loc(address) {
  try {
    var mod = Process.findModuleByAddress(address);
    return mod ? {module: mod.name, offset: address.sub(mod.base).toString()} : {module: '?'};
  } catch (e) { return {module: '?', error: String(e)}; }
}
function hook(name) {
  var address;
  try { address = DebugSymbol.getFunctionByName(name); }
  catch (e) { send({kind: 'symbol_missing', symbol: name, error: String(e)}); return; }
  if (address === null) { send({kind: 'symbol_missing', symbol: name}); return; }
  Interceptor.attach(address, {
    onEnter: function (args) {
      var sig = args[0].toInt32();
      if (sig !== 6 && sig !== 7 && sig !== 11) return;
      this.info = {kind: 'sigaction', symbol: name, signal: sig,
                   caller: loc(this.returnAddress)};
      if (args[1].isNull()) this.info.new_action = null;
      else {
        try {
          var handler = args[1].add(8).readPointer();
          this.info.new_action = {
            flags: '0x' + args[1].readU32().toString(16),
            handler: handler.toString(), location: loc(handler)
          };
        } catch (e) { this.info.new_action_error = String(e); }
      }
      this.oldPtr = args[2];
    },
    onLeave: function (retval) {
      if (!this.info) return;
      this.info.result = retval.toInt32();
      if (!this.oldPtr.isNull() && retval.toInt32() === 0) {
        try {
          var handler = this.oldPtr.add(8).readPointer();
          this.info.old_action = {
            flags: '0x' + this.oldPtr.readU32().toString(16),
            handler: handler.toString(), location: loc(handler)
          };
        } catch (e) { this.info.old_action_error = String(e); }
      }
      send(this.info);
    }
  });
  send({kind: 'hooked', symbol: name});
}
hook('sigaction');
hook('sigaction64');
send({kind: 'hooks_installed'});
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="YOUR_ADB_SERIAL")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--log", type=Path, default=Path("analysis/runtime-logs/sig-layout.jsonl"))
    args = parser.parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    device = frida.get_device_manager().get_device_matching(
        lambda entry: entry.id == args.device, timeout=10
    )
    with args.log.open("w", encoding="utf-8") as output:
        def record(event):
            line = json.dumps(event, sort_keys=True)
            print(line, flush=True)
            output.write(line + "\n")
            output.flush()

        pid = device.spawn(PKG)
        record({"kind": "spawned", "pid": pid})
        session = device.attach(pid)
        script = session.create_script(JS)
        script.on("message", lambda message, data: record(
            message["payload"] if message["type"] == "send"
            else {"kind": "frida_error", "message": message}
        ))
        script.load()
        device.resume(pid)
        record({"kind": "resumed", "pid": pid})
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            time.sleep(1)
            if not any(process.pid == pid for process in device.enumerate_processes()):
                record({"kind": "process_exited", "pid": pid})
                break
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
        record({"kind": "finished", "pid": pid})


if __name__ == "__main__":
    main()
