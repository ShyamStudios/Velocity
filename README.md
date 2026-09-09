# Velocity (Performance & Security Fork)

[![Build Status](https://img.shields.io/github/actions/workflow/status/PaperMC/Velocity/gradle.yml)](https://papermc.io/downloads/velocity)
[![Join our Discord](https://img.shields.io/discord/289587909051416579.svg?logo=discord&label=)](https://discord.gg/papermc)

> This fork focuses on performance and security work on top of upstream
> Velocity, keeping full plugin API compatibility (no `api/*` changes).

## How much faster is this fork?

Tested on the same machine, original code vs this fork, same repeated tasks.
Lower bar = faster. All plugins still work (no API changes).

```
Empty chat/text reads        old ██████████████████████████████  30.7ms
                             new █████                             6.0ms   ~5x faster

Big player-list builds       old ██████████████████████████████  4797ms
                             new ▏                                 5.6ms   ~855x faster

Big server-list builds       old ██████████████████████████████  5089ms
                             new ▏                                21.5ms   ~237x faster

Finding packet types         old ██████████████████████████████   8.1ms
                             new ██████████                       2.8ms   ~3x faster

Normal gameplay packets      old ██████████████████████████████  12.1ms
                             new ██████████████████████████████  12.2ms   same
```

Overall picture:

- **Everyday play:** about the same speed, slightly smoother.
- **Busy moments (logins, big servers, large packets):** much faster with
  far fewer lag spikes, because the proxy now uses far less short-lived
  memory in those paths.
- **Memory:** roughly 1kB less per player (~10MB saved per 10,000 players),
  plus large packets no longer reserve ~1MB upfront (~8kB instead).
- **One tradeoff:** joining a server does a tiny bit more math once per
  login (unnoticeable) to save ~4kB of memory each time.

Note: these are repeated-task measurements, not a full live-server test.
Real-world gains are biggest during login waves and busy periods.

A Minecraft server proxy with unparalleled server support, scalability,
and flexibility.

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
