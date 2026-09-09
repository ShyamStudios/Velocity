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

import java.util.EnumMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Bounded security telemetry.
 *
 * <p>One atomic counter per rejection reason plus a globally throttled "should I log this"
 * permit, so security logging itself can never become a denial-of-service vector: at most one
 * violation line is emitted per interval no matter how hard an attacker floods. Callers pass an
 * already-sanitized address label (honoring {@code enable-player-address-logging}); this class
 * never sees raw addresses, secrets, or payloads.</p>
 */
public final class SecurityMetrics {

  /**
   * Reasons a connection, request, or packet can be shed for security.
   */
  public enum Reason {
    /** Connection arrived faster than the per-IP or global rate allows. */
    CONNECTION_RATE_LIMITED,
    /** Too many simultaneous connections from one source. */
    CONNECTION_CONCURRENT_PER_IP,
    /** Too many simultaneous connections proxy-wide. */
    CONNECTION_CONCURRENT_GLOBAL,
    /** Login attempts arrived faster than allowed (expensive auth path). */
    LOGIN_RATE_LIMITED,
    /** Status requests arrived faster than allowed. */
    STATUS_RATE_LIMITED,
    /** Source is serving a temporary abuse penalty. */
    PENALIZED,
    /** Malformed protocol input failed validation. */
    MALFORMED_PACKET,
    /** Malformed backend (plugin-channel) message ignored. */
    MALFORMED_BACKEND_MESSAGE
  }

  private static final long LOG_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(10);

  private final EnumMap<Reason, AtomicLong> counters = new EnumMap<>(Reason.class);
  private final LongSupplier nanoClock;
  private final AtomicLong lastLogNanos = new AtomicLong(Long.MIN_VALUE);
  private final AtomicLong suppressedLogs = new AtomicLong();

  /**
   * Creates metrics using the system clock.
   */
  public SecurityMetrics() {
    this(System::nanoTime);
  }

  /**
   * Creates metrics with an explicit clock (used by tests).
   *
   * @param nanoClock source of nanosecond timestamps
   */
  public SecurityMetrics(final LongSupplier nanoClock) {
    this.nanoClock = nanoClock;
    for (final Reason reason : Reason.values()) {
      counters.put(reason, new AtomicLong());
    }
  }

  /**
   * Records an event and asks whether a log line may be emitted for it.
   *
   * @param reason what happened
   * @return {@code true} if the caller should log one line for this event
   */
  public boolean record(final Reason reason) {
    counters.get(reason).incrementAndGet();
    return shouldLog();
  }

  /**
   * Asks whether a log line may be emitted, without recording anything. Used when the event
   * was already counted elsewhere (for example by the rate limiter) and the caller only needs
   * the throttle decision.
   *
   * @return {@code true} if the caller should log one line
   */
  public boolean shouldLog() {
    final long now = nanoClock.getAsLong();
    final long last = lastLogNanos.get();
    if (last != Long.MIN_VALUE && now - last < LOG_INTERVAL_NANOS) {
      suppressedLogs.incrementAndGet();
      return false;
    }
    if (lastLogNanos.compareAndSet(last, now)) {
      return true;
    }
    suppressedLogs.incrementAndGet();
    return false;
  }

  /**
   * Returns how many times the reason was recorded.
   *
   * @param reason the reason to query
   * @return the count
   */
  public long count(final Reason reason) {
    return counters.get(reason).get();
  }

  /**
   * Returns how many log lines were suppressed by throttling.
   *
   * @return suppressed log line count
   */
  public long suppressedLogs() {
    return suppressedLogs.get();
  }
}
