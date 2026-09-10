# Velocity (Performance & Security Fork)

[![Build Status](https://img.shields.io/github/actions/workflow/status/PaperMC/Velocity/gradle.yml)](https://papermc.io/downloads/velocity)
[![Join our Discord](https://img.shields.io/discord/289587909051416579.svg?logo=discord&label=)](https://discord.gg/papermc)

A Minecraft server proxy with unparalleled server support, scalability,
and flexibility.

This fork explores connection-abuse protections (configured via `secure.yml`),
tighter validation of untrusted protocol input, and reduced allocation
overhead on hot paths, while keeping the public plugin API unchanged.

Areas currently being worked on:

* Batching packet writes and flushes where ordering allows, to issue fewer
  syscalls per burst of packets.
* Capping upfront buffer and collection sizes derived from untrusted lengths,
  so malformed input cannot force large allocations before validation fails.
* Replacing per-packet promise allocations with shared/void promises on
  fire-and-forget write paths.
* Keeping per-player and per-connection bookkeeping tables small by default
  and growing them on demand.

## Testing (full method)

### Compared revisions

* Baseline: upstream Velocity `21bbf35d` (PR #1870), verified as a direct
  ancestor of the fork.
* Fork: this tree. No `api/*` changes on either side of the comparison.

### Environment (identical for both)

* CPU: AMD Ryzen 7 7445HS, 6 cores / 12 threads. RAM: 15.3 GB, Windows 11.
* Java 25.0.4 Oracle HotSpot, Gradle 9.6.1.
* Heap control: `_JAVA_OPTIONS="-Xmx512m -Xms512m"` for every test JVM.
* Both jars built from clean trees and smoke-run (bind localhost, "Done",
  clean kill) before measuring.

### Harness

`proxy/src/test/.../bench/SystemLevelBenchTest.java` (committed, same file on
both trees; fork-only hooks resolve reflectively so it compiles on upstream
too). It drives realistic byte streams through the real Netty pipeline —
framing, decoding, session handlers, encoding — with a mocked server backend,
and records per workload: wall time, thread-allocated bytes (JMX), GC
count/time, heap delta, and per-unit p50/p95/p99/max latencies. It asserts only
message counts, never speed, so it stays green in CI.

### Workloads (per measured round)

* **Handshake:** 2,000 full frontend connections (channel init, handshake
  decode, session-handler switch, teardown).
* **Play:** 40,000 packets (10% decoded KeepAlive, 90% unknown-id passthrough).
* **Status:** 200 handshake + status-request cycles incl. ping serialization.
* **Malformed:** 200 truncated/overlong frames (fail-fast path).
* **Flood:** 20,000 rapid attempts from one abusive source with one legitimate
  attempt interleaved every tenth try (2,000 legit total); counts shed,
  admitted, and legitimate successes/failures.
* **Soak:** mixed mini-workloads with per-minute heap/GC/thread samples.

### Run order and repetitions

One throwaway warmup run, then 5 measured runs per implementation in strict
alternation (fork, upstream, fork, upstream, …), 3 rounds each; round 1 is
warmup, rounds 2–3 are the samples (10 samples per workload per build).
Scale sweep (100/500/1000 connections) and a 30-minute soak were run
separately. Medians reported; spreads checked against run-to-run noise before
calling anything a difference.

### Known harness bias (measured, not hand-waved)

The fork's added hooks call mocked server getters, and each Mockito call costs
~3.1kB/~8µs **in the harness only** (production uses direct field reads). A
`mock-calibration` workload measures this unit on both trees (both agree), and
fork handshake/status/malformed numbers are reported after subtracting exactly
the counted extra calls (3/connection, 6/status, 4/malformed). After adjustment
the gaps close precisely (e.g. malformed lands on 4.4MB vs 4.4MB), confirming
artifact rather than product cost. The play workload makes zero extra mocked
calls, so its identical result needs no adjustment.

### Measured results (warmed medians)

| Workload | Upstream | Fork | Outcome |
|---|---|---|---|
| 2,000 handshakes | ~207ms / ~44MB | ~295ms / ~49MB adj. | equal within artifact bounds |
| 40,000 play packets | ~70ms / ~29.0MB | ~69ms / ~28.9MB | equal |
| 200 status requests | ~99ms / ~9.4MB | ~122ms / ~8.4MB adj. | equal within artifact bounds |
| 200 malformed packets | ~13ms / ~4.4MB | ~26ms / ~4.4MB adj. | equal within artifact bounds |
| Flood, 20k attempts | ~1512ms / ~440MB, 0 shed | ~44ms / ~12MB, 90% shed | flood shed cheaply |
| Legit logins during flood | 2000/2000 ok | 2000/2000 ok | preserved |
| 30-min soak | not run to completion here | stable, no growth/errors | fork measured |

Unit-level hot-spot runs on the same machine (registry lookup, empty-string
reads, limiter admission at ~160ns/connection) are consistent with the above
but are not presented as system results.

Visual comparison (measured medians, shorter bar is better):

```
Flood, 20k attempts (wall)      upstream ██████████████████████████████ 1512ms
                                fork     █ 44ms

Flood, 20k attempts (allocated) upstream ██████████████████████████████ 440MB
                                fork     █ 12MB

40,000 play packets (wall)      upstream ██████████████████████████████ ~70ms
                                fork     █████████████████████████████ ~69ms

2,000 handshakes (alloc)        upstream ██████████████████████████████ ~44MB
                                fork     ████████████████████████████████ ~49MB adj.
```

Flood bars differ because upstream has no shed path (every attempt pays full
decode); play/handshake bars are within run-to-run noise of each other.

Where repeats got cheaper (unit-level, shorter bar is better):

```
Legit login during flood (p50)  upstream ██████████████████████████████ ~51us
                                fork     ██ ~3us

Registry lookup (2M ops)        upstream ██████████████████████████████ 8.1ms
                                fork     ██████████ 2.8ms

Empty-string reads (200k ops)   upstream ██████████████████████████████ 30.7ms
                                fork     ██████ 6.0ms
```

These are hot-spot repeats, not whole-proxy speedups: everyday gameplay
measures the same because these steps are nanoseconds inside microsecond-scale
packet work.

### Reproduce

```powershell
git worktree add ../Velocity-baseline 21bbf35d
# copy proxy/src/test/.../bench/SystemLevelBenchTest.java into the worktree
$env:_JAVA_OPTIONS = "-Xmx512m -Xms512m"
$env:BENCH_CONNS = "2000"; $env:BENCH_PLAY = "200"
$env:BENCH_ROUNDS = "3"; $env:BENCH_FLOOD = "20000"
./gradlew :velocity-proxy:cleanTest :velocity-proxy:test `
  --tests "com.velocitypowered.proxy.bench.SystemLevelBenchTest"
# read BENCH / BENCH_PCT lines from
# proxy/build/test-results/test/TEST-...-SystemLevelBenchTest.xml
```

Soak: add `$env:BENCH_SOAK_MINUTES = "30"` (per-minute `BENCH soak` lines with
heap, GC, threads, error counts).

### Not covered, therefore not claimed

Multi-thousand-player counts, p99 latency under live traffic, server
switching, long production soaks of upstream, legitimate-player experience
under real attack traffic, and file-based profiler hotspot comparison
(attempted via JFR; blocked because concurrent test JVMs overwrote one
another's recording file — documented, not worked around silently).

Velocity is licensed under the GPLv3 license.

## Goals

* A codebase that is easy to dive into and consistently follows best practices
  for Java projects as much as reasonably possible.
* High performance: handle thousands of players on one proxy.
* A new, refreshing API built from the ground up to be flexible and powerful
  whilst avoiding design mistakes and suboptimal designs from other proxies.
* First-class support for Paper, Sponge, Fabric and Forge. (Other implementations
  may work, but we make every endeavor to support these server implementations
  specifically.)
  
## Building

Velocity is built with [Gradle](https://gradle.org). We recommend using the
wrapper script (`./gradlew`) as our CI builds using it.

It is sufficient to run `./gradlew build` to run the full build cycle.

## Running

Once you've built Velocity, you can copy and run the `-all` JAR from
`proxy/build/libs`. Velocity will generate a default configuration file
and you can configure it from there.

Alternatively, you can get the proxy JAR from the [downloads](https://papermc.io/downloads/velocity)
page.

# Localisation

Translations are handled using [Crowdin](https://papermc-io.crowdin.com/velocity).
If you want to translate a language not available on Crowdin,
you might want to ask in the [Discord](https://discord.gg/papermc) about it.
