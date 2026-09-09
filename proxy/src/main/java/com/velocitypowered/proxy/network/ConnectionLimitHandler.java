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

import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.security.ConnectionRateLimiter;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.net.SocketAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * First inbound handler on accepted (frontend) channels.
 *
 * <p>Runs the cheapest possible abuse check — a few atomics and one bounded map lookup — before
 * any framing, decoding, or session allocation happens. Denied connections are closed without
 * reading further. Per-source checks are skipped when the HAProxy PROXY protocol is in use,
 * because at this stage the remote address is the load balancer shared by every client; the
 * true client address is only known at handshake time, where the login/status limiters (keyed
 * on the PROXY-supplied address) still apply. A new instance is created per channel and holds
 * only that channel's release handle.</p>
 */
public final class ConnectionLimitHandler extends ChannelInboundHandlerAdapter {

  private static final Logger logger = LogManager.getLogger(ConnectionLimitHandler.class);

  private final VelocityServer server;
  private ConnectionRateLimiter limiter;
  private ConnectionRateLimiter.Acquisition acquisition;

  /**
   * Creates a handler bound to the server (the current limiter is resolved per connection so
   * configuration reloads take effect for new connections).
   *
   * @param server the proxy server
   */
  public ConnectionLimitHandler(final VelocityServer server) {
    this.server = server;
  }

  @Override
  public void channelActive(final ChannelHandlerContext ctx) throws Exception {
    final ConnectionRateLimiter current = server.getConnectionRateLimiter();
    if (current == null) {
      // Limiter not initialized yet (pre-start internals or unit tests): fail open.
      super.channelActive(ctx);
      return;
    }
    this.limiter = current;
    final boolean perIp = !server.getConfiguration().isProxyProtocol();
    final SocketAddress remote = ctx.channel().remoteAddress();
    final ConnectionRateLimiter.Attempt attempt =
        current.tryAcquireConnection(remote, perIp);
    if (attempt.decision() != ConnectionRateLimiter.Decision.ALLOWED) {
      // Already counted inside the limiter; only ask for a throttled log line here.
      if (server.getSecurityMetrics().shouldLog() && logger.isWarnEnabled()) {
        logger.warn("Rejected connection from {}: {}", safeLabel(remote),
            describe(attempt.decision()));
      }
      ctx.close();
      return;
    }
    this.acquisition = attempt.acquisition();
    super.channelActive(ctx);
  }

  @Override
  public void channelInactive(final ChannelHandlerContext ctx) throws Exception {
    if (limiter != null && acquisition != null) {
      limiter.release(acquisition);
      acquisition = null;
    }
    super.channelInactive(ctx);
  }

  private static String describe(final ConnectionRateLimiter.Decision decision) {
    return switch (decision) {
      case RATE_LIMITED -> "connecting too fast";
      case TOO_MANY_PER_IP -> "too many simultaneous connections from this source";
      case TOO_MANY_GLOBAL -> "server connection capacity reached";
      case PENALIZED -> "temporarily blocked for repeated violations";
      default -> "denied";
    };
  }

  private String safeLabel(final SocketAddress remote) {
    if (server.getConfiguration().isPlayerAddressLoggingEnabled() && remote != null) {
      return remote.toString();
    }
    return "<address withheld>";
  }
}
