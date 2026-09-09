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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.velocitypowered.proxy.protocol.ProtocolUtils;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

class PacketValidationTest {

  @Test
  void countBounds() {
    assertDoesNotThrow(() -> PacketValidation.checkCount(0, 16, "things"));
    assertDoesNotThrow(() -> PacketValidation.checkCount(16, 16, "things"));
    assertThrows(DecoderException.class, () -> PacketValidation.checkCount(-1, 16, "things"));
    assertThrows(DecoderException.class, () -> PacketValidation.checkCount(17, 16, "things"));
  }

  @Test
  void oversizedPropertyListIsRejected() {
    final ByteBuf buf = Unpooled.buffer();
    try {
      ProtocolUtils.writeVarInt(buf, PacketValidation.MAX_PROFILE_PROPERTIES + 1);
      assertThrows(DecoderException.class, () -> ProtocolUtils.readProperties(buf));
    } finally {
      buf.release();
    }
  }

  @Test
  void negativePropertyCountIsRejected() {
    final ByteBuf buf = Unpooled.buffer();
    try {
      // -1 encodes as five bytes; previously this silently decoded as an empty list.
      ProtocolUtils.writeVarInt(buf, -1);
      assertThrows(DecoderException.class, () -> ProtocolUtils.readProperties(buf));
    } finally {
      buf.release();
    }
  }

  @Test
  void sanePropertyListStillDecodes() {
    final ByteBuf buf = Unpooled.buffer();
    try {
      ProtocolUtils.writeVarInt(buf, 1);
      ProtocolUtils.writeString(buf, "textures");
      ProtocolUtils.writeString(buf, "value");
      buf.writeBoolean(false);
      assertEquals(1, ProtocolUtils.readProperties(buf).size());
    } finally {
      buf.release();
    }
  }

  @Test
  void hostileStringCapCannotOverflow() {
    final ByteBuf buf = Unpooled.buffer();
    try {
      ProtocolUtils.writeString(buf, "abc");
      // 800_000_000 * 3 overflows int to a negative number; a naive check would reject
      // even this 3-byte string. Overflow-safe math must accept it (frame bounds still apply).
      assertEquals("abc", ProtocolUtils.readString(buf, 800_000_000));
    } finally {
      buf.release();
    }
  }
}
