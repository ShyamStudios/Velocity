/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.velocitypowered.proxy.network;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Trusted-source allowlist for the HAProxy PROXY protocol.
 *
 * <p>When PROXY protocol is enabled, the claimed client address comes from a header
 * that anyone with a TCP connection can send. This allowlist restricts which
 * <em>direct TCP peers</em> (your load balancers) may supply that header. An empty
 * list means "allow all" and preserves the historical behavior exactly.</p>
 *
 * <p>Entries are plain IPs ({@code 203.0.113.4}, {@code 2001:db8::1}) or CIDR ranges
 * ({@code 10.0.0.0/8}, {@code 2001:db8::/32}). IPv4 entries never match IPv6
 * addresses and vice versa. All methods are thread-safe and allocate nothing on
 * the match path beyond parsing-free prefix comparison.</p>
 */
public final class ProxyProtocolAllowlist {

  private ProxyProtocolAllowlist() {
    throw new AssertionError();
  }

  /**
   * Pre-parsed allowlist. Compile once per configuration load and reuse on every
   * connection: matching then allocates nothing and never touches DNS.
   */
  public static final class Compiled {

    private final List<Prefix> prefixes;
    private final boolean open;

    private Compiled(final List<Prefix> prefixes, final boolean open) {
      this.prefixes = prefixes;
      this.open = open;
    }
  }

  /**
   * Parses the configured entries once. Invalid entries match nothing (startup
   * validation reports them separately).
   *
   * @param networks configured allowlist
   * @return compiled form
   */
  public static Compiled compile(final List<String> networks) {
    if (networks == null || networks.isEmpty()) {
      return new Compiled(List.of(), true);
    }
    final List<Prefix> prefixes = new ArrayList<>(networks.size());
    for (final String entry : networks) {
      final Prefix prefix = parse(entry);
      if (prefix != null) {
        prefixes.add(prefix);
      }
    }
    return new Compiled(List.copyOf(prefixes), false);
  }

  /**
   * Checks whether the direct TCP peer may send a PROXY header.
   *
   * @param compiled allowlist compiled via {@link #compile}
   * @param remote the direct peer address from the channel
   * @return {@code true} if the header must be honored
   */
  public static boolean isAllowed(final Compiled compiled, final SocketAddress remote) {
    if (compiled == null || compiled.open) {
      return true;
    }
    if (!(remote instanceof InetSocketAddress)) {
      return false;
    }
    final InetAddress address = ((InetSocketAddress) remote).getAddress();
    if (address == null) {
      return false;
    }
    final byte[] got = address.getAddress();
    for (final Prefix prefix : compiled.prefixes) {
      if (matches(prefix, got)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether the direct TCP peer may send a PROXY header. Convenience
   * overload that parses on every call — use {@link #compile} on hot paths.
   *
   * @param networks configured allowlist; empty or {@code null} allows everyone
   * @param remote the direct peer address from the channel
   * @return {@code true} if the header must be honored
   */
  public static boolean isAllowed(final List<String> networks, final SocketAddress remote) {
    return isAllowed(compile(networks), remote);
  }

  /**
   * Validates allowlist entries for configuration fail-closed reporting.
   *
   * @param networks configured allowlist
   * @return human-readable errors, empty when every entry parses
   */
  public static List<String> validate(final List<String> networks) {
    final List<String> errors = new ArrayList<>();
    if (networks == null) {
      return errors;
    }
    for (final String entry : networks) {
      if (entry == null || parse(entry) == null) {
        errors.add("'" + entry + "' is not a valid IP or CIDR range (e.g. 203.0.113.4, "
            + "10.0.0.0/8, 2001:db8::/32).");
      }
    }
    return errors;
  }

  private static boolean matches(final Prefix prefix, final byte[] got) {
    final byte[] want = prefix.network.getAddress();
    if (want.length != got.length) {
      return false;
    }
    int fullBytes = prefix.length / 8;
    int restBits = prefix.length % 8;
    for (int i = 0; i < fullBytes && i < want.length; i++) {
      if (want[i] != got[i]) {
        return false;
      }
    }
    if (restBits != 0 && fullBytes < want.length) {
      final int mask = 0xFF & (0xFF << (8 - restBits));
      return (want[fullBytes] & mask) == (got[fullBytes] & mask);
    }
    return true;
  }

  private static Prefix parse(final String entry) {
    if (entry == null) {
      return null;
    }
    final String trimmed = entry.trim();
    if (trimmed.isEmpty()) {
      return null;
    }
    // IP literals and CIDR only — never hostnames. Besides being unambiguous, this
    // guarantees InetAddress.getByName resolves the literal without touching DNS,
    // so parsing can never stall a connection thread.
    for (int i = 0; i < trimmed.length(); i++) {
      final char c = trimmed.charAt(i);
      final boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
          || (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '/';
      if (!ok) {
        return null;
      }
    }
    try {
      final int slash = trimmed.indexOf('/');
      final InetAddress network;
      final int length;
      if (slash < 0) {
        network = InetAddress.getByName(trimmed);
        length = network.getAddress().length * 8;
      } else {
        network = InetAddress.getByName(trimmed.substring(0, slash).trim());
        length = Integer.parseInt(trimmed.substring(slash + 1).trim());
        if (length < 0 || length > network.getAddress().length * 8) {
          return null;
        }
      }
      return new Prefix(network, length);
    } catch (final Exception e) {
      return null;
    }
  }

  private static final class Prefix {

    final InetAddress network;
    final int length;

    Prefix(final InetAddress network, final int length) {
      this.network = network;
      this.length = length;
    }
  }
}
