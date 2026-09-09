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

import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * A small thread-safe token bucket used for rate limiting.
 *
 * <p>The bucket starts full (a fresh client may burst up to {@code capacity} immediately) and
 * refills continuously at {@code tokensPerSecond}. Checks allocate nothing and take a single
 * short monitor, so sharing one bucket across the Netty worker threads is cheap. Per-IP buckets
 * additionally only contend with checks for the same IP.</p>
 */
public final class TokenBucket {

  private static final long DISABLED = -1L;

  private final double tokensPerSecond;
  private final double capacity;
  private final LongSupplier nanoClock;
  private double available;
  private long lastRefillNanos;

  private TokenBucket(final double tokensPerSecond, final double capacity,
      final LongSupplier nanoClock, final long now) {
    this.tokensPerSecond = tokensPerSecond;
    this.capacity = capacity;
    this.nanoClock = nanoClock;
    this.available = capacity;
    this.lastRefillNanos = now;
  }

  /**
   * Creates a bucket refilling at the given rate, or a disabled always-allow bucket when the
   * rate is not positive. A rate of {@code 0} (or less) therefore means "no limit".
   *
   * @param tokensPerSecond sustained rate; {@code <= 0} disables limiting
   * @param burst maximum burst size; values below {@code 1} are clamped to {@code 1}
   * @return a new bucket
   */
  public static TokenBucket perSecond(final double tokensPerSecond, final double burst) {
    return perSecond(tokensPerSecond, burst, System::nanoTime);
  }

  /**
   * Creates a bucket with an explicit clock (used by tests).
   *
   * @param tokensPerSecond sustained rate; {@code <= 0} disables limiting
   * @param burst maximum burst size; values below {@code 1} are clamped to {@code 1}
   * @param nanoClock source of nanosecond timestamps
   * @return a new bucket
   */
  public static TokenBucket perSecond(final double tokensPerSecond, final double burst,
      final LongSupplier nanoClock) {
    if (tokensPerSecond <= 0) {
      return new TokenBucket(DISABLED, Double.MAX_VALUE, nanoClock, nanoClock.getAsLong());
    }
    return new TokenBucket(tokensPerSecond, Math.max(1, burst), nanoClock,
        nanoClock.getAsLong());
  }

  /**
   * Attempts to consume a single token.
   *
   * @return {@code true} if the action is allowed, {@code false} if rate limited
   */
  public synchronized boolean tryConsume() {
    if (tokensPerSecond == DISABLED) {
      return true;
    }
    final long now = nanoClock.getAsLong();
    long elapsed = now - lastRefillNanos;
    if (elapsed < 0) {
      // Clock moved backwards (NTP adjustment); do not grant extra budget for the jump.
      elapsed = 0;
    }
    lastRefillNanos = now;
    available = Math.min(capacity,
        available + elapsed * (tokensPerSecond / (double) TimeUnit.SECONDS.toNanos(1)));
    if (available >= 1) {
      available -= 1;
      return true;
    }
    return false;
  }
}
