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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Guards connection establishment and pre-authentication request rates.
 *
 * <p>Three layers, cheapest first: temporary abuse penalties, concurrent-connection counts
 * (per source and proxy-wide), then token-bucket rates for connections, login attempts, and
 * status requests. All per-source state lives in a bounded, self-expiring cache (at most
 * {@value #MAX_TRACKED_SOURCES} sources), so an attacker sweeping source addresses cannot grow
 * memory without bound. Every denial feeds the abuse tracker and a bounded metric.</p>
 *
 * <p>Thread safety: safe to call from any Netty worker thread. Per-source records only contend
 * with checks for the same source; the only proxy-wide contention is two atomic integers and
 * one optional token bucket.</p>
 */
public final class ConnectionRateLimiter {

  /** Upper bound on tracked sources; bounds memory under source-address sweeps. */
  static final int MAX_TRACKED_SOURCES = 8192;

  /**
   * Outcome of an admission check.
   */
  public enum Decision {
    /** The connection or request may proceed. */
    ALLOWED,
    /** Denied: arrived faster than the token bucket allows. */
    RATE_LIMITED,
    /** Denied: too many simultaneous connections from this source. */
    TOO_MANY_PER_IP,
    /** Denied: too many simultaneous connections proxy-wide. */
    TOO_MANY_GLOBAL,
    /** Denied: the source is serving a temporary abuse penalty. */
    PENALIZED
  }

  /**
   * Handle for a single admitted connection. Must be released exactly once when the connection
   * closes; double release is ignored defensively.
   */
  public static final class Acquisition {

    private final IpKey key;
    private final boolean perIpTracked;
    private final boolean globalCounted;
    private final AtomicBoolean released = new AtomicBoolean();

    private Acquisition(final IpKey key, final boolean perIpTracked,
        final boolean globalCounted) {
      this.key = key;
      this.perIpTracked = perIpTracked;
      this.globalCounted = globalCounted;
    }

    private static final Acquisition NOOP = new Acquisition(null, false, false);
  }

  /**
   * Result of {@link #tryAcquireConnection(SocketAddress, boolean)}.
   */
  public static final class Attempt {

    private final Decision decision;
    private final Acquisition acquisition;

    private Attempt(final Decision decision, final Acquisition acquisition) {
      this.decision = decision;
      this.acquisition = acquisition;
    }

    /**
     * Returns the admission decision.
     *
     * @return the decision
     */
    public Decision decision() {
      return decision;
    }

    /**
     * Returns the release handle, or {@code null} when the attempt was denied.
     *
     * @return the acquisition, or {@code null} on denial
     */
    public Acquisition acquisition() {
      return acquisition;
    }
  }

  private final SecurityConfig config;
  private final SecurityMetrics metrics;
  private final AbuseTracker abuse;
  private final Cache<IpKey, IpState> states;
  private final TokenBucket globalRateBucket;
  private final AtomicInteger globalConcurrent = new AtomicInteger();

  /**
   * Creates a limiter from configuration, owning its abuse tracker.
   *
   * @param config the security configuration
   * @param metrics shared security metrics
   */
  public ConnectionRateLimiter(final SecurityConfig config, final SecurityMetrics metrics) {
    this(config, metrics, new AbuseTracker(config.getAbuseThreshold(),
        config.getAbuseWindowSeconds(), config.getAbusePenaltySeconds(), 4096));
  }

  /**
   * Creates a limiter with an explicit abuse tracker (used by tests).
   *
   * @param config the security configuration
   * @param metrics shared security metrics
   * @param abuse the abuse tracker to feed
   */
  public ConnectionRateLimiter(final SecurityConfig config, final SecurityMetrics metrics,
      final AbuseTracker abuse) {
    this.config = config;
    this.metrics = metrics;
    this.abuse = abuse;
    this.states = Caffeine.newBuilder()
        .maximumSize(MAX_TRACKED_SOURCES)
        .expireAfterAccess(10, TimeUnit.MINUTES)
        .build();
    this.globalRateBucket = TokenBucket.perSecond(
        config.getMaxNewConnectionsPerSecondGlobal(), config.getMaxNewConnectionsPerSecondGlobal());
  }

  /**
   * Attempts to admit a new TCP connection.
   *
   * @param remote the remote peer address
   * @param applyPerIpLimits whether per-source checks apply. Must be {@code false} when the
   *     address is a load balancer rather than the client (HAProxy PROXY protocol), otherwise
   *     every client behind the balancer would share one tiny budget.
   * @return the attempt result; on {@link Decision#ALLOWED} the acquisition must be released
   *     when the connection closes
   */
  public Attempt tryAcquireConnection(final SocketAddress remote,
      final boolean applyPerIpLimits) {
    final InetAddress address = inetAddressOf(remote);
    if (address == null || !config.isEnabled()) {
      return new Attempt(Decision.ALLOWED, Acquisition.NOOP);
    }
    if (abuse.isPenalized(address)) {
      metrics.record(SecurityMetrics.Reason.PENALIZED);
      return new Attempt(Decision.PENALIZED, null);
    }

    boolean globalCounted = false;
    if (config.getMaxConcurrentConnectionsGlobal() > 0) {
      final int current = globalConcurrent.incrementAndGet();
      if (current > config.getMaxConcurrentConnectionsGlobal()) {
        globalConcurrent.decrementAndGet();
        return deny(address, SecurityMetrics.Reason.CONNECTION_CONCURRENT_GLOBAL,
            Decision.TOO_MANY_GLOBAL);
      }
      globalCounted = true;
    }

    IpKey key = null;
    IpState state = null;
    if (applyPerIpLimits) {
      key = IpKey.of(address);
      state = states.get(key, ignored -> new IpState(config));
      if (config.getMaxConcurrentConnectionsPerIp() > 0) {
        final int current = state.concurrent.incrementAndGet();
        if (current > config.getMaxConcurrentConnectionsPerIp()) {
          state.concurrent.decrementAndGet();
          if (globalCounted) {
            globalConcurrent.decrementAndGet();
          }
          return deny(address, SecurityMetrics.Reason.CONNECTION_CONCURRENT_PER_IP,
              Decision.TOO_MANY_PER_IP);
        }
      }
      if (!state.connectionBucket.tryConsume()) {
        if (config.getMaxConcurrentConnectionsPerIp() > 0) {
          state.concurrent.decrementAndGet();
        }
        if (globalCounted) {
          globalConcurrent.decrementAndGet();
        }
        return deny(address, SecurityMetrics.Reason.CONNECTION_RATE_LIMITED,
            Decision.RATE_LIMITED);
      }
    }

    if (!globalRateBucket.tryConsume()) {
      if (state != null && config.getMaxConcurrentConnectionsPerIp() > 0) {
        state.concurrent.decrementAndGet();
      }
      if (globalCounted) {
        globalConcurrent.decrementAndGet();
      }
      return deny(address, SecurityMetrics.Reason.CONNECTION_RATE_LIMITED, Decision.RATE_LIMITED);
    }

    return new Attempt(Decision.ALLOWED, new Acquisition(key, applyPerIpLimits, globalCounted));
  }

  /**
   * Releases a previously acquired connection.
   *
   * @param acquisition the handle from a successful {@link #tryAcquireConnection} call
   */
  public void release(final Acquisition acquisition) {
    if (acquisition == null || acquisition == Acquisition.NOOP) {
      return;
    }
    if (!acquisition.released.compareAndSet(false, true)) {
      return;
    }
    if (acquisition.globalCounted) {
      globalConcurrent.decrementAndGet();
    }
    if (acquisition.perIpTracked && acquisition.key != null) {
      final IpState state = states.getIfPresent(acquisition.key);
      if (state != null) {
        state.concurrent.decrementAndGet();
      }
    }
  }

  /**
   * Attempts a login (authentication-path) request for rate purposes.
   *
   * @param remote the remote address as known at handshake time (PROXY-aware)
   * @return the decision
   */
  public Decision tryLogin(final SocketAddress remote) {
    return tryBucketed(remote, true, false);
  }

  /**
   * Attempts a status (server-list) request for rate purposes.
   *
   * @param remote the remote address as known at handshake time (PROXY-aware)
   * @return the decision
   */
  public Decision tryStatus(final SocketAddress remote) {
    return tryBucketed(remote, false, true);
  }

  private Decision tryBucketed(final SocketAddress remote, final boolean login,
      final boolean status) {
    final InetAddress address = inetAddressOf(remote);
    if (address == null || !config.isEnabled()) {
      return Decision.ALLOWED;
    }
    if (abuse.isPenalized(address)) {
      metrics.record(SecurityMetrics.Reason.PENALIZED);
      return Decision.PENALIZED;
    }
    final IpState state = states.get(IpKey.of(address), ignored -> new IpState(config));
    final TokenBucket bucket = login ? state.loginBucket : state.statusBucket;
    if (!bucket.tryConsume()) {
      abuse.recordViolation(address);
      final SecurityMetrics.Reason reason = login
          ? SecurityMetrics.Reason.LOGIN_RATE_LIMITED
          : SecurityMetrics.Reason.STATUS_RATE_LIMITED;
      metrics.record(reason);
      return Decision.RATE_LIMITED;
    }
    return Decision.ALLOWED;
  }

  private Attempt deny(final InetAddress address, final SecurityMetrics.Reason reason,
      final Decision decision) {
    abuse.recordViolation(address);
    metrics.record(reason);
    return new Attempt(decision, null);
  }

  private static InetAddress inetAddressOf(final SocketAddress remote) {
    if (remote instanceof InetSocketAddress) {
      return ((InetSocketAddress) remote).getAddress();
    }
    return null;
  }

  /**
   * Returns the current proxy-wide concurrent count (for tests and diagnostics).
   *
   * @return global concurrent connections counted by this limiter
   */
  int globalConcurrent() {
    return globalConcurrent.get();
  }

  private static final class IpState {

    private final TokenBucket connectionBucket;
    private final TokenBucket loginBucket;
    private final TokenBucket statusBucket;
    private final AtomicInteger concurrent = new AtomicInteger();

    private IpState(final SecurityConfig config) {
      this.connectionBucket = TokenBucket.perSecond(
          config.getMaxNewConnectionsPerSecondPerIp(), config.getNewConnectionsBurstPerIp());
      this.loginBucket = TokenBucket.perSecond(
          config.getMaxLoginAttemptsPerSecondPerIp(), config.getLoginAttemptsBurstPerIp());
      this.statusBucket = TokenBucket.perSecond(
          config.getMaxStatusRequestsPerSecondPerIp(), config.getStatusRequestsBurstPerIp());
    }
  }
}
