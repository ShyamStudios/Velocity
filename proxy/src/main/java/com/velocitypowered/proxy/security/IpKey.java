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

package com.velocitypowered.proxy.security;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Normalized map key for per-source tracking.
 *
 * <p>IPv4 addresses are keyed exactly. IPv6 addresses are grouped by /64: a single end site
 * is normally assigned a /64, so grouping there stops trivial evasion by rotating the low
 * 64 bits while still distinguishing unrelated networks. This is a deliberate tradeoff and
 * is documented in {@code SECURITY.md}; penalties built on top are short-lived for exactly
 * this reason.</p>
 */
final class IpKey {

  private static final int KIND_V4 = 4;
  private static final int KIND_V6_64 = 6;
  private static final int KIND_OTHER = 0;

  private final int kind;
  private final long high;
  private final long low;
  private final int hash;

  private IpKey(final int kind, final long high, final long low) {
    this.kind = kind;
    this.high = high;
    this.low = low;
    this.hash = 31 * (31 * kind + Long.hashCode(high)) + Long.hashCode(low);
  }

  /**
   * Creates a key for the given address.
   *
   * @param address the address to key on
   * @return the normalized key
   */
  static IpKey of(final InetAddress address) {
    final byte[] raw = address.getAddress();
    if (raw.length == 4) {
      return new IpKey(KIND_V4, 0, ByteBuffer.wrap(raw).getInt() & 0xFFFFFFFFL);
    }
    if (raw.length == 16) {
      // Group by /64: keep the network half, drop the interface half.
      final ByteBuffer buf = ByteBuffer.wrap(raw);
      return new IpKey(KIND_V6_64, buf.getLong(), 0);
    }
    return new IpKey(KIND_OTHER, 0, Arrays.hashCode(raw));
  }

  @Override
  public boolean equals(final Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof IpKey)) {
      return false;
    }
    final IpKey that = (IpKey) other;
    return this.kind == that.kind && this.high == that.high && this.low == that.low;
  }

  @Override
  public int hashCode() {
    return hash;
  }

  @Override
  public String toString() {
    return "IpKey{kind=" + kind + '}';
  }
}
