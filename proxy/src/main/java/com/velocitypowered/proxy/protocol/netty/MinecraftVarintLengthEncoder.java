/*
 * Copyright (C) 2018-2023 Velocity Contributors
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

package com.velocitypowered.proxy.protocol.netty;

import com.velocitypowered.natives.encryption.JavaVelocityCipher;
import com.velocitypowered.natives.util.Natives;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;
import java.util.List;

/**
 * Handler for appending a length for Minecraft packets.
 */
@ChannelHandler.Sharable
public class MinecraftVarintLengthEncoder extends MessageToMessageEncoder<ByteBuf> {

  public static final MinecraftVarintLengthEncoder INSTANCE = new MinecraftVarintLengthEncoder();

  static final boolean IS_JAVA_CIPHER = Natives.cipher.get() == JavaVelocityCipher.FACTORY;

  /**
   * Packets at or below this size take the single-buffer path: one allocation and one
   * list entry instead of a length buffer plus a retained slice (gathering write).
   * Larger packets keep the zero-copy two-buffer path so big payloads are never copied.
   */
  static final int SINGLE_BUFFER_LIMIT = 256;

  private MinecraftVarintLengthEncoder() {
  }

  @Override
  protected void encode(ChannelHandlerContext ctx, ByteBuf buf,
      List<Object> list) throws Exception {
    final int length = buf.readableBytes();
    final int varintLength = ProtocolUtils.varIntBytes(length);

    if (length <= SINGLE_BUFFER_LIMIT) {
      // Fast path for the common small packets (keepalive, chat, position...).
      // The input buffer is released by the encoder framework after this call.
      final ByteBuf out = IS_JAVA_CIPHER
          ? ctx.alloc().heapBuffer(varintLength + length)
          : ctx.alloc().directBuffer(varintLength + length);
      ProtocolUtils.writeVarInt(out, length);
      out.writeBytes(buf);
      list.add(out);
      return;
    }

    final ByteBuf lenBuf = IS_JAVA_CIPHER
        ? ctx.alloc().heapBuffer(varintLength)
        : ctx.alloc().directBuffer(varintLength);

    ProtocolUtils.writeVarInt(lenBuf, length);
    list.add(lenBuf);
    list.add(buf.retain());
  }
}
