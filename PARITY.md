# mtr Parity Status

How closely this Go port reproduces official [`mtr`](https://github.com/traviscross/mtr)
(pinned as the `refs/mtr` submodule). Reference command:

```
mtr -rwzbc 30 2.80.85.81
```

`-r` report · `-w` wide · `-z` ASN lookup · `-b` show IPs · `-c 30` cycles.

## Summary

| Aspect | Parity |
|--------|--------|
| Bundled flag parsing (`-rwzbc 30`) | **Identical** — `expandShortFlags` mirrors getopt bundling |
| Report header / column widths | **Byte-identical** — same width math as `report.c` |
| Column titles + format strings | **Byte-identical** — `fields.go` transcribes `mtr.c` `data_fields[]` |
| Loss% (`%4.1f%%`), Snt (`%5d`) | **Identical** |
| ASN `-z` (`AS16276` / `AS???`) | **Identical** — Team Cymru DNS TXT, same render |
| Show-IPs `-b` (`host (ip)`) | **Identical** format string |
| Avg / StDev math | **Identical** — same double-then-truncate accumulation (`hop.go`) |
| **RTT decimals on Windows** | **Differs by design** — see below |

The whole table-rendering pipeline is byte-for-byte identical to official mtr.
The command runs cleanly with no blockers.

## Known difference: Windows RTT resolution

The Windows prober uses `IcmpSendEcho` (`iphlpapi.dll`), the same unprivileged
API as legacy WinMTR. Its `RoundTripTime` is reported in **whole milliseconds**,
so on Windows the `Last/Avg/Best/Wrst/StDev` columns render with a `.0` fraction
(`5.0`) where Unix raw-socket mtr — timestamping at microsecond precision —
shows true 0.1 ms granularity (`5.3`).

This is an intentional trade-off (decided 2026-06-26): `IcmpSendEcho` runs
without elevation; matching mtr's microsecond decimals would require a
raw-socket prober **and Administrator privileges** on Windows. The Unix path
(`internal/trace/icmp.go`) already uses the monotonic clock and reproduces
mtr's decimals exactly.

Consequence: a trace captured on **Linux mtr** (microsecond decimals) and the
same trace on the **Windows port** (whole-ms) will show the same layout, ASNs,
hostnames, loss%, and hop structure, but the RTT-derived numbers will differ in
the sub-millisecond digit. LAN/first hops where `RoundTripTime == 0` fall back
to a locally measured send/receive delta.

## Minor Windows behavioral notes

- Don't-Fragment is set unconditionally on the Windows echo (harmless at the
  default 64-byte size).
- Reverse DNS uses Go's `net.DefaultResolver` (3 s timeout, 5 min cache) rather
  than libc `gethostbyaddr`; within a fixed cycle budget this can change *which*
  hops resolve a name vs. show a bare IP, though the `host (ip)` format is
  identical.
- Probing is synchronous per-TTL with a once-per-cycle sleep rather than mtr's
  fully asynchronous sequence-matched send/harvest; this changes pacing and
  total wall-time, not steady-state per-hop RTT/loss.
