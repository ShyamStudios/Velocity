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

import com.google.common.base.Preconditions;
import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.proxy.protocol.MinecraftPacket;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import com.velocitypowered.proxy.protocol.StateRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 * Encodes {@link MinecraftPacket} instances.
 */
public class MinecraftEncoder extends MessageToByteEncoder<MinecraftPacket> {

  private final ProtocolUtils.Direction direction;
  private StateRegistry state;
  private StateRegistry.PacketRegistry.ProtocolRegistry registry;
  // Single-entry cache: same packet classes repeat back-to-back (KeepAlive, chat, etc.).
  // Confined to the owning EventLoop thread, no synchronization needed.
  private Class<? extends MinecraftPacket> lastPacketClass;
  private int lastPacketId;

  /**
   * Creates a new {@code MinecraftEncoder} encoding packets for the specified {@code direction}.
   *
   * @param direction the direction to encode to
   */
  public MinecraftEncoder(ProtocolUtils.Direction direction) {
    this.direction = Preconditions.checkNotNull(direction, "direction");
    this.registry = StateRegistry.HANDSHAKE.getProtocolRegistry(
        direction, ProtocolVersion.MINIMUM_VERSION);
    this.state = StateRegistry.HANDSHAKE;
  }

  private int getPacketIdCached(MinecraftPacket msg) {
    Class<? extends MinecraftPacket> clazz = msg.getClass();
    if (clazz == lastPacketClass) {
      return lastPacketId;
    }
    int id = this.registry.getPacketId(msg);
    lastPacketClass = clazz;
    lastPacketId = id;
    return id;
  }

  @Override
  protected void encode(ChannelHandlerContext ctx, MinecraftPacket msg, ByteBuf out) {
    int packetId = getPacketIdCached(msg);
    ProtocolUtils.writeVarInt(out, packetId);
    msg.encode(out, direction, registry.version);
  }

  @Override
  protected ByteBuf allocateBuffer(ChannelHandlerContext ctx, MinecraftPacket msg,
      boolean preferDirect) throws Exception {
    int hint = msg.encodeSizeHint(direction, registry.version);
    if (hint < 0) {
      return super.allocateBuffer(ctx, msg, preferDirect);
    }

    int packetId = getPacketIdCached(msg);
    int totalHint = ProtocolUtils.varIntBytes(packetId) + hint;
    // Cap absurd hints from malformed packets: allocator will grow on demand.
    if (totalHint > 65536) {
      totalHint = 65536;
    }
    return preferDirect ? ctx.alloc().ioBuffer(totalHint) : ctx.alloc().heapBuffer(totalHint);
  }

  /**
   * Sets the protocol version used for encoding.
   *
   * @param protocolVersion the protocol version to use
   */
  public void setProtocolVersion(final ProtocolVersion protocolVersion) {
    this.registry = state.getProtocolRegistry(direction, protocolVersion);
    // Packet IDs depend on registry (state+version): invalidate cached mapping.
    this.lastPacketClass = null;
  }

  /**
   * Sets the protocol state used for encoding.
   *
   * @param state the state to use
   */
  public void setState(StateRegistry state) {
    this.state = state;
    this.setProtocolVersion(registry.version);
  }

  public ProtocolUtils.Direction getDirection() {
    return direction;
  }
}
