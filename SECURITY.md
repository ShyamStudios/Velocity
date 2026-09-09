# Velocity Fork — Security Model

This document describes what this fork protects against, how to configure it,
and — just as importantly — what it does **not** protect against. Nothing here
should be read as "completely secure" or "DDoS-proof". Every mechanism below
names the attack it mitigates and the assumptions it still relies on.

## Trust boundaries

| Boundary | Trusted party | Untrusted input | What we do |
|---|---|---|---|
| Internet client → proxy TCP | Nobody | Bytes, timing, volume | Validate before allocating; cheap checks before expensive work; shed floods; close on violation |
| Handshake / login (pre-auth) | Nobody | Handshake fields, login packets, status requests | Per-source rate limits; status served cheaply and rate-limited; auth path bounded per source |
| Mojang session servers | Mojang infrastructure | Availability (outages) | Auth runs off the event loops; failures fail closed per login |
| Backend server → proxy | Semi-trusted operator code | Packet contents, plugin-channel messages | Same frame/length validation as clients; malformed backend messages are ignored and counted instead of killing the player |
| Proxy → backend forwarding | Shared secret (modern/BungeeGuard) or network isolation (legacy/none) | Nothing from the client beyond its authenticated profile | Fail closed when modern forwarding is unacknowledged; warn loudly on unauthenticated modes |
| Plugins | Fully trusted code | Must still handle hostile client input safely | Exceptions isolated per handler; no sandboxing (by design) |
| Configuration / console | Operator | Typos, dangerous values | Invalid security values refuse to start; reload keeps the old protections on failure |

## Protections (`secure.yml`)

Created automatically next to `velocity.toml` on first boot. `0` disables an
individual check. All defaults are lenient toward legitimate traffic.

| Key | Default | Mitigates | Rationale |
|---|---|---|---|
| `enabled` | `true` | — | Master switch |
| `max-concurrent-connections-per-ip` | `32` | Socket exhaustion by half-open/idle floods | Households and small LANs never approach this; floods open hundreds |
| `max-new-connections-per-second-per-ip` / `new-connections-burst-per-ip` | `10` / `20` | Connection-creation floods | Launchers open a couple per second; scanners do dozens |
| `max-concurrent-connections-global` | `50000` | Proxy-wide exhaustion | Backstop an order of magnitude above typical peaks; lower on small machines |
| `max-new-connections-per-second-global` | `0` (off) | — | Disabled so legitimate flash crowds are never dropped; per-source and concurrent limits cover floods |
| `max-login-attempts-per-second-per-ip` / `login-attempts-burst-per-ip` | `2` / `4` | CPU/Mojang amplification via the RSA + HTTPS auth path | Retries are human-paced; complements `login-ratelimit` in `velocity.toml` |
| `max-status-requests-per-second-per-ip` / `status-requests-burst-per-ip` | `5` / `10` | List-ping floods (each can cost ping handling and plugin events) | Refreshes are manual; botnets poll constantly |
| `abuse-penalty-threshold` / `abuse-window-seconds` / `abuse-penalty-seconds` | `10` / `60` / `30` | Repeat offenders | Short temporary penalty only — never a permanent ban, so shared addresses recover |

IPv6 sources are grouped by /64 (one end site normally gets a /64), which stops
trivial evasion by rotating the low bits while keeping unrelated networks apart.

## Deployment notes

- **Firewall your backends.** With `player-info-forwarding-mode: legacy` (or
  `none`), anyone reaching a backend directly can impersonate players. The proxy
  logs a warning in this mode. Prefer `modern` with a strong secret.
- **HAProxy PROXY protocol:** per-source TCP-stage limits see the load balancer
  address, so they are skipped in that mode (only the proxy-wide backstop
  applies at TCP time). Handshake-time login/status limits still use the true
  client address from the PROXY header. Firewall the listener so headers cannot
  be spoofed.
- **NAT tradeoffs:** per-source limits and temporary penalties are shared by
  everyone behind one address. Thresholds are set so normal shared use never
  trips them; a sustained attack from behind the same NAT will affect that
  address for the penalty duration. There is no way to distinguish attacker
  from neighbor at this layer.
- **Reload:** `/velocity reload` also reloads `secure.yml`. Invalid values keep
  the previous protections running instead of disabling them.
- **Observability:** rejections increment in-memory counters; at most one
  violation log line is emitted every 10 seconds no matter the flood size, so
  logging cannot be weaponized. No addresses are logged when
  `enable-player-address-logging` is off; secrets, keys, and payloads are never
  logged.

## What is intentionally unchanged

- Cryptography (RSA/Mojang flow, AES-CFB8, HMAC forwarding) is Mojang- or
  protocol-dictated; it is reviewed, not redesigned.
- BungeeCord plugin-channel semantics (a backend can move/kick players) are
  by-design BungeeCord behavior; only malformed messages are now ignored
  instead of disconnecting the player.
- Plugins remain fully trusted code with no sandbox; event exceptions are
  isolated per handler as before.

## Reporting vulnerabilities

Open a private security advisory on the fork's GitHub repository (or contact
the maintainer directly) instead of filing a public issue. Include the version,
`secure.yml` (with any secrets redacted), logs around the event, and steps to
reproduce.
