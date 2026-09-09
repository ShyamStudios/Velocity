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

/**
 * Defense-in-depth checks for legacy player-information forwarding.
 *
 * <p>Legacy (BungeeCord-compatible) forwarding encodes fields separated by {@code \0} bytes,
 * which backends split on. A separator byte smuggled into the virtual host would shift every
 * subsequent field from the backend's point of view. The handshake path already strips
 * everything from the first {@code \0} ({@code HandshakeSessionHandler.cleanVhost}), so this
 * is unreachable with the current callers — it exists so the invariant holds no matter which
 * caller builds a forwarding address in the future. Clean input passes through byte-identical.</p>
 */
public final class ForwardingValidator {

  private ForwardingValidator() {
    throw new AssertionError();
  }

  /**
   * Removes anything from the first {@code \0} byte onward from a virtual host used in legacy
   * forwarding construction.
   *
   * @param vhost the virtual host, possibly {@code null}
   * @return the sanitized host, or {@code ""} when {@code null}
   */
  public static String sanitizeVhost(final String vhost) {
    if (vhost == null) {
      return "";
    }
    final int nul = vhost.indexOf('\0');
    return nul < 0 ? vhost : vhost.substring(0, nul);
  }
}
