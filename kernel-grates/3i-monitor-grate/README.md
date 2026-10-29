# Single-chokepoint 3i monitor (`monitor_grate`)

A reference monitor for the 3i subsystem that governs an **entire tree of
grates and cages from one interposition** — a handler on `make_threei_call`.
It is a worked example of why interposing the 3i *forwarding API* is strictly
more expressive than interposing individual syscalls or the control-plane
operations directly.

## The idea

In 3i, a **grate** mediates a **cage**'s syscalls; any cage can become a grate
by registering handlers. A grate performs three kinds of privileged 3i
operation:

| operation                  | what it does                                  |
|----------------------------|-----------------------------------------------|
| `make_threei_call(nr, …)`  | forward/execute a syscall on a cage's behalf  |
| `register_handler(…)`      | start interposing a cage's syscall            |
| `copy_data_between_cages(…)`| read/write another cage's memory             |

If every one of these is issued **through** `make_threei_call` (the
*uniform-entry* convention — see below), then a single handler registered on
`make_threei_call` sees them all. `monitor_grate` is that handler. It
dispatches on the inner operation:

- **`register_handler`** → may this grate interpose that target cage?
- **`copy_data_between_cages`** → may this caller touch that src/dst cage?
- **any real syscall forward** → default-deny by syscall number, no
  third-cage argument smuggling, and a per-`(syscall, arg)` whitelist for
  *injected* arguments (the grate substituting its own memory into a cage's
  syscall).

### Authority model: subtree-scoped

Lineage is read from the real process tree via `/proc/<pid>/stat`, so it is
authoritative. A grate may `register_handler`-on or `copy_data`-from **only
pids inside its own subtree** (itself + its descendants). It may **not** reach
*up* to an ancestor or *sideways* to another tenant.

## The demo chain

```
./monitor_grate ./tenant_grate ./atk_grate ./cage
     monitor         tenant A      attacker    victim
```

- **`monitor_grate`** — the trusted monitor. Arms one handler on
  `make_threei_call`; the whole subtree inherits governance across fork+exec.
- **`tenant_grate`** — a benign tenant that holds a secret in memory and forks
  the attacker. It exists so the attacker has an *ancestor* to attack.
- **`atk_grate`** — a malicious grate. Using **ordinary** `register_handler` /
  `copy_data_between_cages` calls (routed through `make_threei_call` ), it tries 
  to reach outside its subtree, up to tenant A.
- **`cage`** — the victim; just opens a file.

What the attacker attempts, and the monitor's verdict:

| attacker action                                    | verdict |
|----------------------------------------------------|---------|
| `register_handler` on its **own cage**             | ALLOW   |
| `copy_data` from its **own cage** (in `h_open`)    | ALLOW   |
| forward the cage's `open` (with an injected path)  | ALLOW   |
| `copy_data` from **tenant A** (steal memory)       | DENY    |
| `register_handler` on **tenant A** (hijack syscalls)| DENY   |

### Expected output

```
[mon] monitor armed on make_threei_call -> <mon>; subtree governed
[tenantA] <pid> holding secret @ 0x..., attacker=<atk>
[mon] ALLOW register_handler: grate=<atk> nr=2 target=<cage>
[mon] ALLOW copy_data: caller=<atk> src=<cage> dst=<atk>
[atk] copy cage->self (in-subtree): rc=18 path="/tmp/mon_real.dat"
[mon] ALLOW forward: caller=<atk> nr=2 primary=<cage>
[cage] open -> 3 (errno=0)
[mon] DENY copy_data: caller=<atk> src=<tenantA> dst=<atk> OUTSIDE its subtree
[atk] STEAL tenantA memory: rc=-1
[mon] DENY register_handler: grate=<atk> target=<tenantA> OUTSIDE its subtree
[atk] HIJACK tenantA open: rc=-1
[mon] ===== chain exit: 0 =====
```
