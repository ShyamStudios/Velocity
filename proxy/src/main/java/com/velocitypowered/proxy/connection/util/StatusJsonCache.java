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

package com.velocitypowered.proxy.connection.util;

import com.google.gson.Gson;
import com.velocitypowered.api.proxy.server.ServerPing;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Remembers the most recently serialized status response.
 *
 * <p>Server-list floods usually repeat the identical ping dozens of times per second while
 * nothing on the proxy changes. Re-serializing the same object through Gson every time is pure
 * waste, so an exact {@code (serializer, ping)} repeat reuses the previous JSON. Anything that
 * differs — player count, sample, MOTD, serializer — recomputes normally. A single entry means
 * memory use is constant (one retained response) and concurrent updates are harmless: entries
 * are immutable and the field is volatile, so every reader sees a consistent triple.</p>
 */
public final class StatusJsonCache {

  private static final class Entry {

    final Gson serializer;
    final ServerPing ping;
    final String json;

    private Entry(final Gson serializer, final ServerPing ping, final String json) {
      this.serializer = serializer;
      this.ping = ping;
      this.json = json;
    }
  }

  private volatile @Nullable Entry last;

  /**
   * Serializes the ping, reusing the previous result for an identical repeat.
   *
   * @param serializer the version-appropriate Gson instance
   * @param ping the ping to serialize
   * @return the JSON response
   */
  public String serialize(final Gson serializer, final ServerPing ping) {
    final Entry cached = last;
    if (cached != null && cached.serializer == serializer && cached.ping.equals(ping)) {
      return cached.json;
    }
    final StringBuilder json = new StringBuilder();
    serializer.toJson(ping, json);
    final String rendered = json.toString();
    last = new Entry(serializer, ping, rendered);
    return rendered;
  }
}
