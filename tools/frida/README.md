# Frida probes

These scripts reproduce selected live-device observations. Pass your ADB serial as the first argument to `frida_signal_watch.py`, or use `--device` for the argparse-based probes; `YOUR_ADB_SERIAL` is a placeholder. Keep captures under the ignored `analysis/` directory.

Use `frida_metadata_trace.py` to capture the runtime metadata and `frida_binary_probe.py` to compare protected ELF windows. `frida_signal_watch.py`, `frida_sig_layout.py`, and `frida_unity_crash_probe.py` cover the Poco signal investigation; `summarize_tls_capture.py` extracts a sanitized TLS summary from a local PCAP. See [runtime findings](../../docs/RUNTIME_FINDINGS.md) for results and limits.
