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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.google.gson.Gson;
import com.velocitypowered.api.proxy.server.ServerPing;
import java.util.List;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.Test;

class StatusJsonCacheTest {

  private static ServerPing ping(final int online) {
    return new ServerPing(new ServerPing.Version(766, "1.20.5"),
        new ServerPing.Players(online, 500, List.of()), Component.text("motd"), null);
  }

  @Test
  void identicalRepeatReusesInstance() {
    final StatusJsonCache cache = new StatusJsonCache();
    final Gson gson = new Gson();
    final String first = cache.serialize(gson, ping(3));
    final String second = cache.serialize(gson, ping(3));
    assertSame(first, second, "identical repeat must skip serialization");
  }

  @Test
  void changedPingRecomputes() {
    final StatusJsonCache cache = new StatusJsonCache();
    final Gson gson = new Gson();
    final String first = cache.serialize(gson, ping(3));
    final String second = cache.serialize(gson, ping(4));
    assertNotSame(first, second);
    assertEquals(new Gson().toJson(ping(4)), second);
  }

  @Test
  void differentSerializerRecomputes() {
    final StatusJsonCache cache = new StatusJsonCache();
    final String first = cache.serialize(new Gson(), ping(3));
    final String second = cache.serialize(new Gson(), ping(3));
    assertNotSame(first, second, "serializer identity is part of the key");
    assertEquals(first, second);
  }
}
