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

import static com.velocitypowered.proxy.protocol.util.NettyPreconditions.checkFrame;

/**
 * Centralized bounds for attacker-controlled protocol values.
 *
 * <p>All checks fail by throwing the shared quiet decoder exception (no stack trace,
 * no logging at the check site), so failed validation can never become a logging
 * denial-of-service vector. Callers are expected to let the exception propagate to
 * {@code MinecraftConnection}, which closes only the affected connection.</p>
 */
public final class PacketValidation {

  /**
   * Maximum number of properties accepted in a single GameProfile property list.
   *
   * <p>Rationale: Mojang-issued profiles carry at most a couple of properties ( texture data
   * and, rarely, one more). Sixteen leaves generous headroom for custom setups while bounding
   * per-list work during login and player-info handling.</p>
   */
  public static final int MAX_PROFILE_PROPERTIES = 16;

  /**
   * Maximum number of bytes a VarInt may occupy on the wire.
   */
  public static final int MAX_VARINT_BYTES = 5;

  private PacketValidation() {
    throw new AssertionError();
  }

  /**
   * Validates an element count before a collection is populated from the wire.
   *
   * @param count the decoded count
   * @param max the maximum acceptable count for this context
   * @param what short description used in the debug-only failure message
   */
  public static void checkCount(final int count, final int max, final String what) {
    checkFrame(count >= 0, "Got a negative-length %s (%s)", what, count);
    checkFrame(count <= max, "Bad %s size (got %s, maximum is %s)", what, count, max);
  }

  /**
   * Validates a profile property list size.
   *
   * @param size the decoded property count
   */
  public static void checkProfileProperties(final int size) {
    checkCount(size, MAX_PROFILE_PROPERTIES, "profile property list");
  }

  /**
   * Validates a VarInt-prefixed byte length against a character cap using overflow-safe math.
   *
   * @param length the decoded byte length
   * @param cap the maximum string size in characters
   */
  public static void checkStringByteLength(final int length, final int cap) {
    checkFrame(length >= 0, "Got a negative-length string (%s)", length);
    // Deliberately computed in long: (cap * 3) as int would overflow for hostile caps.
    checkFrame((long) length <= (long) cap * 3L, "Bad string size");
  }
}
