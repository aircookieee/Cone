"""Observe Unity's installed signal handler without replacing it (Poco F3).

The arm64 signal frame offsets follow Android bionic's ucontext_t and the
kernel's sigcontext. This script changes no signal disposition; it attaches
to the handler pointer observed during startup and records entry arguments.
"""

import argparse
import json
import time
from pathlib import Path

import frida


JS = r"""
function loc(address) {
  var m = Process.findModuleByAddress(address);
  return {address: address.toString(), module: m ? m.name : '?',
          offset: m ? address.sub(m.base).toString() : null};
}
var watched = {};
var sa = DebugSymbol.getFunctionByName('sigaction');
var query = new NativeFunction(sa, 'int', ['int', 'pointer', 'pointer']);
var oldAction = Memory.alloc(160);
var lastDisposition = {};
function sampleDisposition() {
  [6, 7, 11].forEach(function (sig) {
    try {
      if (query(sig, ptr(0), oldAction) !== 0) return;
      var handler = oldAction.add(8).readPointer();
      var flags = oldAction.readU32();
      var signature = handler.toString() + '/' + flags;
      if (lastDisposition[sig] !== signature) {
        lastDisposition[sig] = signature;
        send({kind: 'disposition', signal: sig, handler: loc(handler),
              flags: '0x' + flags.toString(16)});
      }
    } catch (e) { send({kind: 'disposition_error', signal: sig, error: String(e)}); }
  });
}
Interceptor.attach(sa, {
  onEnter: function (args) {
    var sig = args[0].toInt32();
    if (sig !== 6 && sig !== 7 && sig !== 11) return;
    if (args[1].isNull()) return;
    var handler = args[1].add(8).readPointer();
    var module = Process.findModuleByAddress(handler);
    if (!module || module.name !== 'libunity.so') return;
    var key = handler.toString();
    send({kind: 'unity_handler_installed', signal: sig, handler: loc(handler),
          flags: '0x' + args[1].readU32().toString(16)});
    if (watched[key]) return;
    watched[key] = true;
    Interceptor.attach(handler, {
      onEnter: function (handlerArgs) {
        var event = {kind: 'unity_handler_entered', signal: handlerArgs[0].toInt32()};
        try {
          event.si_code = handlerArgs[1].add(8).readS32();
          event.si_addr = handlerArgs[1].add(16).readPointer().toString();
        } catch (e) { event.siginfo_error = String(e); }
        try {
          // uc_mcontext is 0xb0 into arm64 ucontext_t; its pc is at 0x108.
          var uc = handlerArgs[2];
          event.fault_address = uc.add(0xb0).readPointer().toString();
          event.fault_pc = loc(uc.add(0x1b8).readPointer());
          event.fault_sp = uc.add(0x1b0).readPointer().toString();
        } catch (e) { event.context_error = String(e); }
        send(event);
      }
    });
    send({kind: 'handler_hooked', handler: loc(handler)});
  }
});
sampleDisposition();
setInterval(sampleDisposition, 100);
send({kind: 'hook_ready'});
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="YOUR_ADB_SERIAL")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--log", type=Path, default=Path("analysis/runtime-logs/unity-crash-probe.jsonl"))
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

        pid = device.spawn("com.bilibili.sirius")
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
