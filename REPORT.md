# nsjail hardening report

- Upstream repo: https://github.com/google/nsjail (default branch `master`)
- Base: upstream `master` at `d8415bc` ("Merge pull request #371 from mcc0nnell/fix/newapi-recursive-readonly")
- Fork: https://github.com/b84330808/nsjail
- Date: 2026-11-03

| # | Fork branch | Commit SHA | Files | Status |
|---|---|---|---|---|
| 1 (main) | `hardening-unotify-bounds` | `54b591e4e0aa0f7583037d84e07955dac46ddf59` | `unotify/syscall.cc`, `unotify/syscall_defs.h`, `tests/unotify_syscall_test.cc` (new), `Makefile` | built, tested, pushed |
| 2 (optional) | `hardening-caps-bounds` | `87ce197d7fc1d01f6cef7a6ac0901047f366a712` | `caps.cc` | built, tested, pushed |

Both are single commits on top of upstream `master`, authored `b84330808 <b84330808@gmail.com>`, with no trailers (no Co-Authored-By).
The two branches are independent: either can be submitted alone.

Suggested order: submit #1 first. #2 is small and purely defensive (it changes no current behavior), so it is lower value and could wait.

---

## Change 1: unotify, decode tracee memory only within the bytes actually copied

### PR title

```
unotify: decode tracee memory only within the bytes actually copied
```

### PR body draft

```
The unotify decoder runs in the supervisor and parses memory that the
sandboxed process controls: path strings, argv/envp, sockaddrs and
struct open_how. It decoded those buffers through C arrays, pointer
casts and pointer arithmetic, with lengths taken from the syscall
arguments rather than from what process_vm_readv() actually copied.
That is less than requested when a buffer ends at an unmapped page.

This change reads tracee memory through one helper that returns the
number of bytes copied, and decodes only through std::span views
bounded by that number:

- sockaddr: decoded only when the whole addrlen was copied (otherwise
  the kernel fails the syscall with EFAULT), and only when it is long
  enough for its family (sockaddr_in, RFC 2133 sockaddr_in6). Before,
  a short or partially readable sockaddr was reported with zero-filled
  fields the tracee never supplied.
- AF_UNIX: the last byte of sun_path is no longer overwritten with a
  NUL. That cut the last character of 108-byte pathnames, and a
  connect() to the 107-byte abstract name "\0AAA...AZ" showed up in
  the report as "@AAA...A\000".
- argv/envp: one template for 32- and 64-bit pointer arrays, using
  only pointers that were copied in full.
- open_how: decoded only when the 24-byte VER0 struct was copied in
  full, which openat2() also requires.

unotify/syscall.cc now has no clang -Wunsafe-buffer-usage warnings
(16 before, 2 of them in syscall_defs.h). The generated kafel policy
is byte-identical.

Testing:
- New tests/unotify_syscall_test, run by `make test`, decodes fake
  notifications against its own memory, including buffers that end
  right before a PROT_NONE page. 10 of its checks fail on master and
  all pass with this change. It is also clean under ASan+UBSan.
- `make test` on Linux 6.18 gives the same results as master, plus
  the new test. The failures I see need network access, pasta or
  desktop apps, and fail the same way on master.
- --seccomp_unotify reports for a shell/python workload (execve
  argv/envp, file opens, IPv4 sendto, AF_UNIX connect) are identical
  before and after.

I used Claude Code to write this change.
```

### What the patch does

The supervisor-side decoder in `unotify/syscall.cc` reads memory from the jailed process, which controls its contents, with `process_vm_readv()`.

- New `readTraceeMem(pid, addr, std::span<std::byte>)` returns the number of bytes actually copied. `process_vm_readv()` returns partial counts inside a single iovec at an unmapped page; I checked this in this container, where reading 128 bytes with only 8 mapped returned `ret=8`.
- `readStringFromMem`: `std::array` + `std::span::first(len)` + `std::find` for the NUL, instead of `buf[ret] = '\0'` + `std::string(buf)`.
- `readStringArrayFromMem`: the duplicated 32-bit and 64-bit branches (C arrays, `int` counters) become one `readStringArray<PtrT>` template that iterates `std::span(ptrs).first(len / sizeof(PtrT))`.
- `parseSockaddr`:
  - Decodes only if all `addrlen` bytes were copied.
  - `loadFromBytes<T>(span, min_len, out)` replaces `(struct sockaddr_in*)&ss`-style casts and enforces per-family minimum lengths.
  - AF_UNIX: `sa.subspan(offsetof(sockaddr_un, sun_path))` replaces `sun->sun_path + 1` pointer arithmetic, and the `sun_path[107] = '\0'` write is removed. That write was the real bug.
- `ArgRole::OHOW`: decodes only if the full 24-byte `open_how` was copied. Before, it read `how.resolve` after checking only for 8 bytes.
- `getAbsPath`: `std::array` buffer. A `readlink()` result that fills the buffer is treated as possibly truncated, and the code falls back to the raw path.
- `decodeSyscallArgs` / `parseSyscall` / `buildKafelPolicy`: `std::span` and range-for instead of `args[i]` over raw pointers and index loops over the table. A `static_assert` ties `seccomp_data::args` and `SyscallDef::args` to the same extent. The unused `kTracedSyscallCount` is removed.

### Build and test commands (exact) and output

Environment: Ubuntu 24.04 container, kernel `6.18.44-fc-v230`, running as root, gcc 13.3.0, clang 18.1.3, libprotoc 3.21.12, libnl-route-3 3.7.0.
User, mount, PID and net namespaces **work** in this container, so the real binary was exercised, not just compiled.

Dependencies:

```bash
apt-get install -y libprotobuf-dev protobuf-compiler libnl-route-3-dev flex bison autoconf libtool pkg-config strace
```

#### Build

```bash
git checkout hardening-unotify-bounds && git submodule update --init && make -j8
```

The build (with `-Wall -Wextra -Werror`) succeeds before and after. The only warnings are kafel's pre-existing `Makefile:27: warning: overriding recipe for target 'test'`.

#### Basic run

```bash
./nsjail -Mo --chroot / -- /bin/true; echo exit=$?
```

```
[I][2026-11-03T15:35:07+0000] Mode: STANDALONE_ONCE
...
[I][2026-11-03T15:35:07+0000] Executing '/bin/true' for '[STANDALONE MODE]'
[I][2026-11-03T15:35:07+0000] pid=2310 ([STANDALONE MODE]) exited with status: 0, (PIDs left: 0)
exit=0
```

#### Regression test: new test against the OLD decoder (before)

The test is compiled against upstream's `unotify/syscall.cc` and `syscall_defs.h`:

```bash
mkdir -p old/unotify
git show upstream/master:unotify/syscall.cc     > old/unotify/syscall.cc
git show upstream/master:unotify/syscall_defs.h > old/unotify/syscall_defs.h
g++ -O2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -fPIE -Wall -Wextra -Werror -Ikafel/include -Iold -I. \
  -std=c++20 -fno-exceptions -Wno-unused -Wno-unused-parameter \
  tests/unotify_syscall_test.cc old/unotify/syscall.cc logs.cc util.cc config.pb.cc unotify/unotify.pb.cc \
  -o unotify_syscall_test_before -pie -lpthread -lprotobuf
./unotify_syscall_test_before; echo exit=$?
```

```
tests/unotify_syscall_test.cc:96: EXPECT(rec.res.net_endpoint == "@" + std::string(sizeof(sun.sun_path) - 2, 'A') + "Z") failed
tests/unotify_syscall_test.cc:109: EXPECT(rec.res.net_endpoint == expected) failed
tests/unotify_syscall_test.cc:111: EXPECT(rec.res.net_path.path == expected) failed
tests/unotify_syscall_test.cc:177: EXPECT(!rec.res.has_net) failed
tests/unotify_syscall_test.cc:182: EXPECT(!rec.res.has_net) failed
tests/unotify_syscall_test.cc:195: EXPECT(!rec.res.has_net) failed
tests/unotify_syscall_test.cc:196: EXPECT(rec.res.net_endpoint.empty()) failed
tests/unotify_syscall_test.cc:205: EXPECT(!rec.res.has_net) failed
tests/unotify_syscall_test.cc:298: EXPECT(rec.res.path1.mode == unotify::Stat_Path_Mode_UNSPECIFIED) failed
tests/unotify_syscall_test.cc:299: EXPECT(rec.res.path1.mode_extra.empty()) failed
10 check(s) failed
exit=1
```

The failures, by line:

- 96: max-length abstract name, last byte lost.
- 109/111: unterminated 108-byte pathname truncated.
- 177/182: short `sockaddr_in` / `sockaddr_in6` decoded from zero fill.
- 195/196/205: partially readable `sockaddr_in6` / abstract name decoded anyway.
- 298/299: partially readable `open_how` decoded.

#### Regression test: patched (after)

```bash
make tests/unotify_syscall_test && ./tests/unotify_syscall_test; echo exit=$?
```

```
exit=0
```

Under ASan+UBSan (gcc), it is also clean:

```bash
g++ -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -Wextra -Werror \
  -Ikafel/include -I. -std=c++20 -fno-exceptions -Wno-unused -Wno-unused-parameter \
  tests/unotify_syscall_test.cc unotify/syscall.cc logs.cc util.cc config.pb.cc unotify/unotify.pb.cc \
  -o unotify_syscall_test_asan -lpthread -lprotobuf && ./unotify_syscall_test_asan; echo asan exit=$?
```

```
asan exit=0
```

The clang sanitizer runtime is not installed in this container, so clang was used only for compile checks: `clang++ -fsyntax-only -Wall -Wextra -Werror` on the test, `unotify/syscall.cc` and `sandbox.cc`, all OK.

#### Safe Buffers check (clang `-Wunsafe-buffer-usage`)

```bash
clang++ -fsyntax-only -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I. -Ikafel/include -std=c++20 -fno-exceptions \
  -Wunsafe-buffer-usage unotify/syscall.cc 2>&1 | grep -c "warning: "
```

- Before (upstream tree): `16`. That is 14 in `unotify/syscall.cc` and 2 in `unotify/syscall_defs.h`.
- After: `0`.

#### End-to-end with the real binary and `--seccomp_unotify`

`sock.py` connects to the abstract AF_UNIX name `"\0" + "A"*106 + "Z"`:

```bash
./nsjail -q -Mo --chroot / --seccomp_unotify --seccomp_unotify_report rep.txt -- /usr/bin/python3 -I sock.py
grep -o 'endpoint: "@A*[^"]*"' rep.txt
```

Middle `A`s are elided here:

```
before: endpoint: "@AAA...(106 x A)...AAA\000"
after:  endpoint: "@AAA...(106 x A)...AAAZ"
```

A general workload was also run with both binaries:

- `ls`, `cat` of `/etc` files, `cd` with relative paths, `env FOO=bar /bin/true arg1 arg2`.
- python3 doing an IPv4 UDP `sendto`, an AF_UNIX `connect` to a pathname, and `os.open`.

Both reports had 2069 lines and were **identical**.

#### Full `make test`, before and after

`make test` stops at the first failing case, and one early case fails in this container on upstream too. So both trees were run with `make -i test`, which runs every case, and the per-case results were compared:

```bash
# before: separate worktree of upstream/master
git worktree add ../wt-before upstream/master && cd ../wt-before && git submodule update --init && make -j8
make -i test > make-test-before.log 2>&1
# after
cd nsjail && make -i test > make-test-after.log 2>&1
grep -c 'PASS:' make-test-*.log; grep -c 'FAIL:' make-test-*.log
diff <(grep FAIL: make-test-before.log) <(grep FAIL: make-test-after.log)   # -> no output
```

| | PASS | FAIL |
|---|---|---|
| upstream `master` | 50 | 38 |
| `hardening-unotify-bounds` | 51 | 38 |

- The extra PASS is `./tests/unotify_syscall_test`.
- The FAIL set is identical, line for line. All 38 failures are environmental and fail the same way on master:
  - 19 need outbound network or pasta (`pasta-*`, `traffic-*`, `nat-ip4/6-only`, `socks5`, `connect`, `dns_http_host_to_guest`).
  - 16 configs need desktop apps, busybox or files not present here (`bash-with-fake-geteuid`, `static-busybox-with-execveat`, `home-documents-with-xorg-no-net`, `firefox-*`, `chromium-*`, times 2 mount backends).
  - 2 are `--rw` `/run/user/0` cases.
  - 1 is `setpriv --groups 1234`, which returns 0 instead of 255 in this container.
- All unit tests pass, along with the basic sanity tests, both mount backends' tmpfs/bind/ro/noexec tests, and the seccomp tests.

The kafel policy string built by `buildKafelPolicy()` is byte-identical before and after (1420 bytes, compared with `cmp`).

---

## Change 2 (optional): caps, bounds-check accesses to the capability sets

### PR title

```
caps: bounds-check accesses to the capability sets
```

### PR body draft

```
getCaps() returned a raw pointer to a thread-local array, and the
get/set helpers indexed it with CAP_TO_INDEX(cap) without checking the
index against the two elements that capget()/capset() exchange.

This keeps the capability sets in a caller-owned std::array and looks
up a capability's element through a helper that rejects out-of-range
capabilities. An out-of-range capability reads as not set, and
requesting one makes initNs() fail, as an unpermitted capability
already does.

No capability in capNames is out of range today (the highest is
CAP_CHECKPOINT_RESTORE, 40), so behavior doesn't change. A capability
>= 64 added to the table later would fail closed instead of reading
and writing past the array. caps.cc now builds without clang
-Wunsafe-buffer-usage warnings (5 before).

Testing: `make test` gives the same results as master. CapInh, CapPrm,
CapEff, CapBnd and CapAmb inside the jail are identical before and
after for: the default; --cap CAP_NET_RAW --cap CAP_SYS_ADMIN;
--keep_caps; --cap CAP_BPF --cap CAP_CHECKPOINT_RESTORE (second array
element); --disable_clone_newuser --cap CAP_NET_ADMIN; and
--user 99999 --cap CAP_KILL.

I used Claude Code to write this change.
```

### Commands and output

```bash
git checkout hardening-caps-bounds && make -j8        # builds with -Werror, no new warnings
clang++ -fsyntax-only -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I. -Ikafel/include -std=c++20 -fno-exceptions \
  -Wunsafe-buffer-usage caps.cc 2>&1 | grep -c "^caps.cc.*warning"   # before: 5, after: 0
make -i test > make-test-caps.log 2>&1                 # PASS=50 FAIL=38, FAIL set identical to master
```

Capability sets inside the jail, from `-- /bin/grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status` with each config. The before and after outputs were compared with `diff` and are identical:

```
default                              CapInh..CapAmb all 0000000000000000                [exit=0]
--cap CAP_NET_RAW --cap CAP_SYS_ADMIN all 0000000000202000                              [exit=0]
--keep_caps                          all 000001ffffffffff                               [exit=0]
--cap CAP_CHECKPOINT_RESTORE --cap CAP_BPF  all 0000018000000000                        [exit=0]
--disable_clone_newuser --cap CAP_NET_ADMIN all 0000000000001000                        [exit=0]
--user 99999 --group 99999 --cap CAP_KILL   all 0000000000000020                        [exit=0]
IDENTICAL
```

---

## Competing PR search

Method:

- Listed all upstream PRs (213, all states) with `gh api -X GET search/issues -f q='repo:google/nsjail is:pr' --paginate`.
- Fetched every PR head with `git fetch upstream '+refs/pull/*/head:refs/remotes/upstream-pr/*'` (219 refs).
- Diffed each against its merge base and listed the files it touches.
- PRs from before 2026-04-03 have no merge base in the shallow clone. They predate the unotify module (added in `ee2d05e`, 2026-04-03), and their trees have no `unotify/` directory.

Results:

- **`unotify/syscall.cc` / `unotify/syscall_defs.h`**: no open or closed-unmerged PR touches them. Merged PRs that did are already in the base: #291 (trace statx), #308 (syscall numbers in the policy, 11 more path syscalls).
- **Other unotify PRs**:
  - #290 (closed, unmerged) "unotify: bound retained syscall statistics": `unotify/stats.cc`, a different issue (map growth).
  - #293 (merged): stats report writing.
  - #341 (open): docs and fuzz harnesses for nstun/kafel; no unotify code.
  - Issue #372 (open): denylist configs vs `SECCOMP_RET_USER_NOTIF`; unrelated to the decoder.
- **`caps.cc`**: only #296 (closed, unmerged) "Harden jail mounts, capabilities, and nstun networking defaults". It changed the CAP_SETPCAP fail-closed logic in `initNs()`, not the capability-array accessors. No open PR touches `caps.cc`.
- **Bounds/span work elsewhere**, avoided as instructed:
  - #333 (open) "nstun: preserve bounds in selected network buffer paths with std::span".
  - #366 (open) "nstun: add a bounds-checked reader for IP parsing".
  - #331 (closed by the author deleting their fork; no maintainer comment) nstun ByteReader.
  - #335 (closed by the author) "util: add optional -fbounds-safety annotation for readFromFd". The author closed it because `-fbounds-safety` is C-only and nsjail is C++. This patch uses standard C++20 `std::span`/`std::array`, which the existing `-std=c++20` build already supports.
  - Neither #331 nor #335 has maintainer comments.
- **Keyword searches** with `gh api search/issues`: `unotify`, `sockaddr`, `process_vm_readv`, `span`, `bounds` (PRs and issues). Nothing else relevant.
- **Merge-conflict check** with `git merge-tree`, counting only conflicts that are new compared with current master:
  - `hardening-caps-bounds`: no new conflicts with any open PR.
  - `hardening-unotify-bounds`: new conflicts only in `Makefile`, with #380, #366 and #322. All three also append to the one-line `TEST_BINS = ...` list. That is the usual trivial conflict whoever merges second resolves. No conflicts in source files.

## Policy notes

- **CONTRIBUTING**: Google Individual CLA is required (the user has signed it); review happens through GitHub PRs. It also says "Before you start working on a larger contribution, you should get in touch with us first through the issue tracker".
  - Change 1 is bigger than most recently merged hardening PRs: about 280 changed lines in `syscall.cc` plus a 329-line test, vs. #308 at +71/−1 and #329 at +117/−3.
  - Options: open an issue first, as CONTRIBUTING asks for larger work, or split it if the maintainer asks. A natural split is (a) the sockaddr/open_how bounds and the AF_UNIX fix with the test, then (b) the remaining span/range-for conversions.
- **Missing policy files**: upstream `master` has no AGENTS.md, CLAUDE.md, PR template or AI policy. `.github/` holds only `workflows/dockerpush.yml`, and CONTRIBUTING doesn't mention AI. **No ban on AI-assisted contributions was found.** The PR bodies disclose it in their last line, as requested.
- **Upstream CI** (`dockerpush.yml`) only runs `docker build` (`make clean && make`). It does not run `make test`.
- **Commit identity**: `b84330808 <b84330808@gmail.com>` as author and committer. No `Co-Authored-By` or other trailer, so the CLA bot only sees the user.
- **Upstream untouched**: nothing was pushed, commented, or opened upstream. The `upstream` remote's push URL was set to `DISABLED` in this clone.

## Patch Rewards category

nsjail is a Tier 1 project per the task.

- **Category**: memory-safety, "secure-by-design" hardening. The program rules list "migrating C-style buffers to C++ containers" as an example of qualifying work, and that is what both changes do (`std::span`/`std::array` with explicit bounds, Safe Buffers style). Each change makes its file build clean under clang `-Wunsafe-buffer-usage` (16 → 0 and 5 → 0).
- **Why change 1 counts**: it hardens a parser of untrusted input, since the privileged supervisor decodes memory the sandboxee controls. It fixes a real decoding defect (the `sun_path[107] = '\0'` overwrite), stops it from decoding bytes that were never copied, and adds a regression test that fails before and passes after.
- **Not a one-liner or a fuzz harness**: neither change falls in the excluded categories.
- **Change 2** is purely defensive. It has no current out-of-bounds and no behavior change, so expect it to be valued at the low end, if at all.
- **Rules to keep in mind**: at most 3 patches per month; amounts are at the Rewards Panel's discretion. The Tier 1 memory-safety multipliers (2x, and 3x for "Core infrastructure data parsers") were advertised only until the end of 2025.
- **Unverified**: `bughunters.google.com` is blocked by this cloud session's network policy, so the rule details above come from search-result summaries, not the live page. Please check https://bughunters.google.com/about/rules/4928084514701312 and the scope file in https://github.com/google/bughunters before submitting.
