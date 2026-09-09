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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.security.ConnectionRateLimiter;
import com.velocitypowered.proxy.security.SecurityConfig;
import com.velocitypowered.proxy.security.SecurityMetrics;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.Test;

class ConnectionLimitHandlerTest {

  private static VelocityServer serverWith(final ConnectionRateLimiter limiter,
      final SecurityMetrics metrics) {
    final VelocityServer server = mock(VelocityServer.class);
    final VelocityConfiguration config = mock(VelocityConfiguration.class);
    when(config.isProxyProtocol()).thenReturn(false);
    when(config.isPlayerAddressLoggingEnabled()).thenReturn(false);
    when(server.getConfiguration()).thenReturn(config);
    when(server.getConnectionRateLimiter()).thenReturn(limiter);
    when(server.getSecurityMetrics()).thenReturn(metrics);
    return server;
  }

  private static ChannelHandlerContext contextFor(final String ip) throws Exception {
    final Channel channel = mock(Channel.class);
    when(channel.remoteAddress())
        .thenReturn(new InetSocketAddress(InetAddress.getByName(ip), 50000));
    final ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
    when(ctx.channel()).thenReturn(channel);
    return ctx;
  }

  @Test
  void allowedConnectionPropagatesActive() throws Exception {
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter = new ConnectionRateLimiter(SecurityConfig.DEFAULT,
        metrics);
    final VelocityServer server = serverWith(limiter, metrics);
    final ChannelHandlerContext ctx = contextFor("10.8.0.1");
    final ConnectionLimitHandler handler = new ConnectionLimitHandler(server);
    handler.channelActive(ctx);
    verify(ctx, never()).close();
    verify(ctx).fireChannelActive();
    handler.channelInactive(ctx);
  }

  @Test
  void perIpFloodIsShedAndReleased() throws Exception {
    final SecurityConfig config = new SecurityConfig(true, 2, 0, 20, 0, 0, 0, 4, 0, 10,
        Integer.MAX_VALUE, 60, 0);
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter = new ConnectionRateLimiter(config, metrics);
    final VelocityServer server = serverWith(limiter, metrics);

    final ChannelHandlerContext first = contextFor("10.9.0.1");
    final ChannelHandlerContext second = contextFor("10.9.0.1");
    final ChannelHandlerContext third = contextFor("10.9.0.1");
    new ConnectionLimitHandler(server).channelActive(first);
    new ConnectionLimitHandler(server).channelActive(second);
    verify(first, never()).close();
    verify(second, never()).close();

    new ConnectionLimitHandler(server).channelActive(third);
    verify(third).close();
    assertTrue(metrics.count(SecurityMetrics.Reason.CONNECTION_CONCURRENT_PER_IP) > 0);
  }

  @Test
  void releaseFreesPerIpSlot() throws Exception {
    final SecurityConfig config = new SecurityConfig(true, 1, 0, 20, 0, 0, 0, 4, 0, 10,
        Integer.MAX_VALUE, 60, 0);
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter = new ConnectionRateLimiter(config, metrics);
    final VelocityServer server = serverWith(limiter, metrics);

    final ConnectionLimitHandler handler = new ConnectionLimitHandler(server);
    final ChannelHandlerContext ctx = contextFor("10.10.0.1");
    handler.channelActive(ctx);
    verify(ctx, never()).close();

    final ChannelHandlerContext intruder = contextFor("10.10.0.1");
    new ConnectionLimitHandler(server).channelActive(intruder);
    verify(intruder).close();

    handler.channelInactive(ctx);
    final ChannelHandlerContext next = contextFor("10.10.0.1");
    new ConnectionLimitHandler(server).channelActive(next);
    verify(next, never()).close();
  }

  @Test
  void uninitializedLimiterFailsOpen() throws Exception {
    final VelocityServer server = mock(VelocityServer.class);
    when(server.getConnectionRateLimiter()).thenReturn(null);
    final ChannelHandlerContext ctx = contextFor("10.11.0.1");
    new ConnectionLimitHandler(server).channelActive(ctx);
    verify(ctx, never()).close();
  }

  @Test
  void embeddedChannelEndToEnd() {
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter = new ConnectionRateLimiter(SecurityConfig.DEFAULT,
        metrics);
    final VelocityServer server = serverWith(limiter, metrics);
    final EmbeddedChannel channel = new EmbeddedChannel();
    channel.pipeline().addLast(new ConnectionLimitHandler(server));
    channel.pipeline().fireChannelActive();
    // Default embedded remote is not IP-keyable, so admission must fail open.
    assertTrue(channel.isOpen());
    // Releasing must not close the channel; it only returns limiter budget.
    channel.pipeline().fireChannelInactive();
    assertTrue(channel.isOpen());
    channel.finishAndReleaseAll();
  }
}
