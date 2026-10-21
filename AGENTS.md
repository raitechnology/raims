# AGENTS.md — raims

Rai Multicast Services: `ms_server`, a link-state pub/sub mesh. Nodes
authenticate with ed25519 keys, flood adjacency, compute routes that
tolerate loops and redundant links, and bridge every protocol the fleet
speaks onto one subject space: native mesh/tcp (`ev_tcp_transport`,
`ev_tcp_aes`), PGM multicast (`ev_pgm_transport`, openpgm), RV
(`ev_rv_transport`, sassrv — `ms_server` is also an rvd replacement),
redis (raids), NATS (natsmd), OMM (omm), telnet console and a web/
websocket front (`ev_web`). Namespace `rai::ms`. Depends on raikv,
raimd, sassrv, raids, natsmd, omm, openpgm_st, h3lib, linecook,
rdbparser, libdecnumber.

## Workspace layout (injinj fleet convention)

- This repo is one of the `injinj` siblings. Every dependency is a sibling
  checkout (`../raikv`, `../raimd`, `../sassrv`, `../raids`, `../natsmd`, `../omm`, `../openpgm`, `../h3`, `../linecook`, `../rdbparser`, `../libdecnumber`); headers come from
  `-I../<dep>/include` and libraries from
  `../<dep>/FC43_x86_64/lib64/lib<dep>.a`. There is no install step between
  siblings — build the dependency, then build this repo.
- Dependencies are declared once, in `build_depends.mak`
  (`<dep>_dep := MAJOR.MINOR`, the rpm BuildRequires minimum). `./deps.sh`
  clones missing siblings from it, `./deps.sh -b` also builds them in
  dependency order, `./deps.sh -s` prints the commit of this repo and every
  sibling (the only record of what a release was built from).
- Whole-fleet build order lives in `~/injinj/GNUmakefile` (`make build`):
  openpgm → raikv → libdecnumber → raimd → linecook → lzf → rdbparser → h3 →
  HdrHistogram_c → sassrv → raids → natsmd → omm → raims → rvcache →
  raimdapi → ossl.

## Build

- `make` → `FC43_x86_64/bin`, `FC43_x86_64/lib64`. The build dir is
  `$(short_dist)$(lsb_dist_ver)_$(uname_m)$(port_extra)`: Fedora 43 →
  `FC43_x86_64`, Rocky 9.5 → `ROCKY9.5_x86_64`.
- `make port_extra=-g` → debug build in `FC43_x86_64-g`.
  `make port_extra=-mingw` → Windows cross build in `FC43_x86_64-mingw`
  (mingw64 toolchain; links the siblings' *master* checkouts).
- `make -j8` is safe; the makefile dependencies are complete. One trap: the
  **first `-j` run right after a compile error** can fail test executables
  with bogus undefined references (symbols from this repo's own lib)
  because they link against a library left half-updated by the failed run.
  Run plain `make` once, then `-j` works again. It is not a missing
  dependency.
- Warnings are clean. A new warning is a defect.
- If a sibling's public headers changed, rebuild the sibling first. A link
  warning like `lib<dep>.so.1.N, needed by ../<x>/.../lib<x>.so, not found`
  means sibling `<x>` was built against an older `<dep>` — rebuild `<x>`;
  at run time that warning is a hard failure (for a one-off test run,
  `ln -s ../<dep>/FC43_x86_64/lib64/lib<dep>.so /tmp/shim/lib<dep>.so.1.N`
  and `LD_LIBRARY_PATH=/tmp/shim` works, but fix the build).
- Ad hoc test program: capture the makefile's own lines once —
  `touch src/<any>.cpp; make -n | grep -- '-c src/<any>.cpp'` and
  `make -n | grep -- '-o FC43_x86_64/bin/' | head -1` — then reuse the
  compile line (minus `-c/-o`) and the link line's `-Wl,-rpath` list +
  `FC43_x86_64/lib64/libraims.a` + the lib tail. If new code pulls in a
  sibling the existing binaries never needed (`DSO missing from command
  line`), append `-L../<dep>/FC43_x86_64/lib64 -l<dep>`.
- Windows: `make port_extra=-mingw dist_win` → `FC43_x86_64-mingw/dist/raims-<ver>-<build>-win64{.zip,-setup.exe,-debug.zip}`
  (NSIS installer from `win/`; installs `ms_server` as a Windows service
  with an evaluation config so an evaluator gets a local daemon on 7500).
  `-debug.zip` is the split debuginfo (`win/dist-strip.sh`). The zip's
  `SOURCES.txt` (`deps.sh -s`) must show no `-dirty` for a release.
  `make dist_win` outlives a single shell timeout — run it detached.

## Versioning and release

- Version is `major_num.minor_num.patch_num-build_num` in `.copr/Makefile`
  (included by the GNUmakefile). `make spec_version` prints the
  `raims_dep := MAJOR.MINOR` line dependents pin in `build_depends.mak`.
- `rpm/raims.spec` carries placeholders (`Version: 999.999`, release
  `99999`, `BuildRequires: <dep> _<dep>_dep`); `make srpm` substitutes them
  from `build_depends.mak`. Keep the `_ensure_git` line in
  `.copr/Makefile`: COPR's `make_srpm` chroot has no git and every
  `$(shell git …)` would silently expand empty.
- COPR: `injinj/dev` builds the `dev` branch of github.com/injinj/raims
  on push (webhook); `injinj/rel` builds github.com/raitechnology/raims.
  Remotes: `origin` = raitechnology (release), `ii` = injinj (dev).
  Chroots: epel-7/8/9/10, fedora-43/44/45/rawhide, x86_64.
- ABI convention: a dependent's `Requires` is `MAJOR.MINOR`, its
  `BuildRequires` the full version, and MINOR is bumped with any change to
  the C++ ABI of a public header. Bump `minor_num` here when public
  headers change, then re-pin and rebuild dependents.
- Link only against installable sibling libraries (`$(lnk_lib)`), never a
  sibling's object files.
- Signed rpms are published to https://www.raitechnology.com/repo/
  (COPR rel → download → sign → createrepo → rsync; tooling in `~/injinj/rel`).
- Windows builds are published to https://www.raitechnology.com/raimdapi/
  (same page as raimdapi) and as a winget manifest (`RaiTechnology.RaiMS`
  in the raitechnology/winget-pkgs fork).

## Code conventions

- C++11, two-space indent, `/* … */` block comments, aligned member
  comments; snake_case functions/variables, CamelCase types. System headers
  first, then project headers.
- Errors are return codes / status enums; no exceptions, no RTTI in library
  code (`NO_STL=1` must still build). Raw pointers and placement-new over
  the repo's allocators are the norm; copy how neighbouring code allocates.
- Keep the generated `CMakeLists.txt` out of your edits — it is derived
  from the GNUmakefile (and slated for removal).

## Layout

- `include/raims/` (40+ headers). Orientation:
  - `session.h` — the node: owns `UserDB` (peers, keys, auth state),
    `SubDB` (`sub.h`, `sub_list.h`, `pat.h`: local + peer interest, bloom
    per peer), transports and the console.
  - `transport.h` + `ev_*_transport.h` — one class per protocol; all feed
    the same `EvPublish` path.
  - `adjacency.h`, `adj_graph.h`, `peer.h`, `user_db.h` — link state:
    adjacency records, graph, forwarding set computation.
  - `msg.h`, `caba_msg_buf.h`, `send_window.h` — the mesh message format
    (CABA) and reliable send window.
  - `auth.h`, `crypt.h`, `ed25519.h`, `ec25519.h`, `aes.h`, `kdf.h`,
    `poly1305.h`, `sha512.h` — crypto (vendored implementations; the
    `*test` binaries are their vectors).
  - `config_tree.h`, `parse_config.h`, `gen_config.h` — the yaml config
    model (`services`, `users`, `transports`, `parameters`, `groups`).
  - `console.h`, `ev_telnet.h`, `ev_web.h` — operator interfaces.
- `src/` (38 files), `test/` (`test_conn`, `test_tcp_aes`, `ms_test_adj`
  for the adjacency/route computation, crypto vectors).
- Configs in the repo root (`con.yaml`, `rv.yaml`, `net.yaml`, `square*.yaml`,
  `run2.yaml`, …) are lab topologies; `run.sh`/`start.sh`/`moo.sh`/`ovh.sh`
  launch multi-node labs in xterms. `configtest/` holds config parser
  cases. `web/` is the embedded web UI (served via `ev_web_tar`).
- `doc/` — <!-- TODO: list -->; `ChangeLog.md` is maintained by hand.

## Running

- `ms_server -d <config.yaml> -u <user> -t <tport>.<listen|connect> …`
  (`-t` repeats; `-c` opens the console). Single-node rv daemon for tests:
  `ms_server -d con.yaml -t rv.listen` (RV on 7500, see `con.yaml`).
- `ms_gen_key` creates service/user key pairs for a config;
  `parse_config` validates a yaml file.
- The lab scripts assume a build dir name — `run.sh` still says
  `FC38_x86_64`; adjust or symlink. <!-- TODO: fix or document -->

## Contracts and gotchas

- The interesting structure is runtime, not static: which transport a
  message leaves on is decided by the forwarding set computed from the
  adjacency graph and the peers' subscription blooms. Read
  `ms_test_adj` and `adj_graph.h` before reasoning about delivery; a call
  graph of `EvPoll` will not tell you.
- `EvSocket` virtual dispatch: every transport is an `EvConnection`
  subclass; `process()`/`on_msg()` are resolved per socket at runtime.
- RV transport is sassrv's `EvRvService`; OMM transport consumes omm's
  envelope contract (`EvPublish.hdr_len`); redis transport is raids.
  Behavioural bugs usually belong to the sibling, fix them there.
- Config keys (`pri`/`pub`/`salt_data`/`pass_data`) in the lab yaml
  files are lab secrets, fine to read, never reuse outside the lab.
- No OMM *provider* — raims consumes OMM only. Say so in any OMM example.

## Tests

- Crypto vectors: `aestest curvetest dsatest kdftest mactest polytest
  shatest sigtest`. Routing: `ms_test_adj`. Transport: `test_conn`,
  `test_tcp_aes`. <!-- TODO: canonical invocations and expected output -->

## Open items / history

<!-- TODO: fill from ChangeLog.md / git log -->
