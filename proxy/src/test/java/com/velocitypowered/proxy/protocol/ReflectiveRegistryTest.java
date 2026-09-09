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

package com.velocitypowered.proxy.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import io.netty.buffer.ByteBuf;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

/**
 * Protocol plugins (notably LimboAPI) build {@code ProtocolRegistry} instances reflectively,
 * bypassing field initializers. Registration and decoding on such instances must degrade to the
 * plain map path instead of throwing {@link NullPointerException}.
 *
 * <p>Uses a fresh registry so static game state is never polluted.</p>
 */
class ReflectiveRegistryTest {

  static final class DummyPacket implements MinecraftPacket {

    @Override
    public void decode(final ByteBuf buf, final ProtocolUtils.Direction direction,
        final ProtocolVersion version) {
    }

    @Override
    public void encode(final ByteBuf buf, final ProtocolUtils.Direction direction,
        final ProtocolVersion version) {
    }

    @Override
    public boolean handle(final MinecraftSessionHandler handler) {
      return true;
    }
  }

  @Test
  void registerAndDecodeWithUninitializedCache() throws Exception {
    final StateRegistry.PacketRegistry outer =
        new StateRegistry.PacketRegistry(ProtocolUtils.Direction.SERVERBOUND, StateRegistry.PLAY);
    final StateRegistry.PacketRegistry.ProtocolRegistry registry =
        outer.getProtocolRegistry(ProtocolVersion.MINECRAFT_1_20_2);

    // Simulate reflective construction: initializers never ran.
    final Field cache = StateRegistry.PacketRegistry.ProtocolRegistry.class
        .getDeclaredField("fastIdCache");
    cache.setAccessible(true);
    cache.set(registry, null);

    final Method map = StateRegistry.class.getDeclaredMethod("map", int.class,
        ProtocolVersion.class, boolean.class);
    map.setAccessible(true);
    final StateRegistry.PacketMapping mapping = (StateRegistry.PacketMapping)
        map.invoke(null, 0x42, ProtocolVersion.MINECRAFT_1_20_2, false);

    outer.register(DummyPacket.class, DummyPacket::new, mapping);

    assertInstanceOf(DummyPacket.class, registry.createPacket(0x42));
    assertEquals(0x42, registry.getPacketId(new DummyPacket()));
  }
}
