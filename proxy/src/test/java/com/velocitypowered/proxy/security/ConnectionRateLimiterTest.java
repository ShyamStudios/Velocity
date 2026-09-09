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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.netty.channel.local.LocalAddress;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class ConnectionRateLimiterTest {

  private static SecurityConfig config(final int concurrentPerIp, final int ratePerIp,
      final int burstPerIp) {
    return new SecurityConfig(true, concurrentPerIp, ratePerIp, burstPerIp,
        0, 0, 0, 4, 0, 10, Integer.MAX_VALUE, 60, 0);
  }

  private static InetSocketAddress addr(final String ip) throws UnknownHostException {
    return new InetSocketAddress(InetAddress.getByName(ip), 25565);
  }

  @Test
  void perIpConcurrentCap() throws Exception {
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config(2, 0, 20), metrics);
    final InetSocketAddress first = addr("10.0.0.1");
    final InetSocketAddress second = addr("10.0.0.2");

    final ConnectionRateLimiter.Attempt one = limiter.tryAcquireConnection(first, true);
    final ConnectionRateLimiter.Attempt two = limiter.tryAcquireConnection(first, true);
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED, one.decision());
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED, two.decision());

    final ConnectionRateLimiter.Attempt third = limiter.tryAcquireConnection(first, true);
    assertEquals(ConnectionRateLimiter.Decision.TOO_MANY_PER_IP, third.decision());
    assertNull(third.acquisition());
    assertEquals(1, metrics.count(SecurityMetrics.Reason.CONNECTION_CONCURRENT_PER_IP));

    // Another source is unaffected.
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(second, true).decision());

    limiter.release(one.acquisition());
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(first, true).decision());

    // Double release is ignored rather than corrupting counts.
    limiter.release(one.acquisition());
    limiter.release(two.acquisition());
  }

  @Test
  void perIpRateCap() throws Exception {
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config(0, 1, 1), metrics);
    final InetSocketAddress remote = addr("10.0.1.1");
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(remote, true).decision());
    assertEquals(ConnectionRateLimiter.Decision.RATE_LIMITED,
        limiter.tryAcquireConnection(remote, true).decision());
    assertEquals(1, metrics.count(SecurityMetrics.Reason.CONNECTION_RATE_LIMITED));
  }

  @Test
  void globalConcurrentCap() throws Exception {
    final SecurityConfig config = new SecurityConfig(true, 0, 0, 20, 1, 0, 0, 4, 0, 10,
        Integer.MAX_VALUE, 60, 0);
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config, new SecurityMetrics());
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(addr("10.1.0.1"), true).decision());
    assertEquals(ConnectionRateLimiter.Decision.TOO_MANY_GLOBAL,
        limiter.tryAcquireConnection(addr("10.1.0.2"), true).decision());
  }

  @Test
  void penaltiesBlockFurtherAttempts() throws Exception {
    final SecurityConfig config = new SecurityConfig(true, 1, 0, 20, 0, 0, 0, 4, 0, 10,
        2, 60, 30);
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config, new SecurityMetrics());
    final InetSocketAddress remote = addr("10.2.0.1");
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(remote, true).decision());
    // Two denials reach the threshold of 2...
    assertEquals(ConnectionRateLimiter.Decision.TOO_MANY_PER_IP,
        limiter.tryAcquireConnection(remote, true).decision());
    assertEquals(ConnectionRateLimiter.Decision.TOO_MANY_PER_IP,
        limiter.tryAcquireConnection(remote, true).decision());
    // ...so the next attempt is shed by penalty without further work.
    assertEquals(ConnectionRateLimiter.Decision.PENALIZED,
        limiter.tryAcquireConnection(remote, true).decision());
  }

  @Test
  void disabledLimiterAllowsEverything() throws Exception {
    final SecurityConfig config = new SecurityConfig(false, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 60, 30);
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config, new SecurityMetrics());
    final InetSocketAddress remote = addr("10.3.0.1");
    for (int i = 0; i < 100; i++) {
      assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
          limiter.tryAcquireConnection(remote, true).decision());
    }
  }

  @Test
  void loadBalancerModeSkipsPerIpTracking() throws Exception {
    final SecurityMetrics metrics = new SecurityMetrics();
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config(1, 1, 1), metrics);
    final InetSocketAddress balancer = addr("10.4.0.1");
    for (int i = 0; i < 50; i++) {
      assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
          limiter.tryAcquireConnection(balancer, false).decision(),
          "shared balancer address must not consume per-IP budget");
    }
    assertEquals(0, metrics.count(SecurityMetrics.Reason.CONNECTION_CONCURRENT_PER_IP));
    assertEquals(0, metrics.count(SecurityMetrics.Reason.CONNECTION_RATE_LIMITED));
  }

  @Test
  void unkeyableAddressesFailOpen() {
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config(1, 1, 1), new SecurityMetrics());
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryAcquireConnection(new LocalAddress("unkeyable"), true).decision());
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryLogin(new LocalAddress("unkeyable")));
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED,
        limiter.tryStatus(new LocalAddress("unkeyable")));
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED, limiter.tryLogin(null));
  }

  @Test
  void loginAndStatusBucketsAreIndependent() throws Exception {
    final SecurityConfig config = new SecurityConfig(true, 0, 0, 20, 0, 0, 1, 1, 100, 100,
        Integer.MAX_VALUE, 60, 0);
    final ConnectionRateLimiter limiter =
        new ConnectionRateLimiter(config, new SecurityMetrics());
    final InetSocketAddress remote = addr("10.5.0.1");
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED, limiter.tryLogin(remote));
    assertEquals(ConnectionRateLimiter.Decision.RATE_LIMITED, limiter.tryLogin(remote));
    // Exhausting logins must not affect status budget.
    assertEquals(ConnectionRateLimiter.Decision.ALLOWED, limiter.tryStatus(remote));
    assertSame(ConnectionRateLimiter.Decision.ALLOWED, limiter.tryStatus(remote));
  }
}
