"""Observe native file probes and process/signal calls during an arm64 game spawn."""

import sys
import time
import frida

DEVICE_ID = sys.argv[1] if len(sys.argv) > 1 else "YOUR_ADB_SERIAL"
PKG = "com.bilibili.sirius"

INTEREST = ["status", "task", "wchan", "syscall", "mounts", "maps",
            "build.prop", "su", "magisk", "xposed", "substrate", "busybox",
            "supersu", "chainfire", "test-keys", "frida", "gadget", "27042",
            "tracerpid"]

JS = """
var INTEREST = %s;
function interesting(path) {
  if (!path) { return false; }
  var p = path.toLowerCase();
  for (var i = 0; i < INTEREST.length; i++) {
    if (p.indexOf(INTEREST[i]) >= 0) { return true; }
  }
  return false;
}
function sym(name) {
  try { return DebugSymbol.getFunctionByName(name); }
  catch (e) { return null; }
}
[["open", 0], ["openat", 1], ["fopen", 0]].forEach(function (pair) {
  var addr = sym(pair[0]);
  if (addr === null) { send({kind: "sym-missing", fn: pair[0]}); return; }
  (function (nm, ad, idx) {
    Interceptor.attach(ad, { onEnter: function (args) {
      var p = "(null)";
      try { p = args[idx].readCString(); } catch (e) {}
      if (interesting(p)) { send({kind: "file", fn: nm, path: p}); }
    }});
  })(pair[0], addr, pair[1]);
  send({kind: "hooked", fn: pair[0]});
});
["kill", "tgkill", "abort", "exit", "_exit", "ptrace"].forEach(function (name) {
  var addr = sym(name);
  if (addr === null) { send({kind: "sym-missing", fn: name}); return; }
  (function (nm, ad) {
    Interceptor.attach(ad, { onEnter: function (args) {
      var info = {kind: "call", fn: nm, a0: args[0].toString(), a1: args[1].toString()};
      try { info.a2 = args[2].toInt32(); } catch (e) {}
      if (nm === "tgkill" || nm === "kill") {
        try {
          info.caller = Thread.backtrace(this.context, Backtracer.FUZZY).map(function (a) {
            var m = Process.findModuleByAddress(a);
            return (m ? m.name.split("/").pop() : "?");
          }).slice(0, 10).join("<");
        } catch (e) { info.caller = "bt-err"; }
      }
      send(info);
    }});
  })(name, addr);
  send({kind: "hooked", fn: name});
});
Process.setExceptionHandler(function (ex) {
  var info = {kind: "exception", type: ex.type};
  try { info.pc = ex.context.pc.toString(); } catch (e) {}
  try {
    var m = Process.findModuleByAddress(ex.context.pc);
    if (m) { info.module = m.name; info.offset = ex.context.pc.sub(m.base).toString(); }
  } catch (e) {}
  send(info);
  return false;
});
send({kind: "hooks-installed"});
""" % str(INTEREST)

def on_message(message, data):
    if message["type"] == "send":
        print("FRIDA-MSG " + str(message["payload"]), flush=True)
    elif message["type"] == "error":
        print("FRIDA-ERR " + str(message.get("stack", message)), flush=True)

mgr = frida.get_device_manager()
dev = mgr.get_device_matching(lambda d: d.id == DEVICE_ID, timeout=10)
print("spawning " + PKG, flush=True)
pid = dev.spawn(PKG)
session = dev.attach(pid)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
dev.resume(pid)
print("resumed pid=" + str(pid), flush=True)
for i in range(15):
    time.sleep(10)
    try:
        alive = any(p.pid == pid for p in dev.enumerate_processes())
    except Exception as e:
        print("enum-error " + str(e), flush=True)
        break
    if not alive:
        print("process died", flush=True)
        break
print("done", flush=True)
