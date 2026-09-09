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
import com.github.benmanes.caffeine.cache.Ticker;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

/**
 * Tracks repeated violations per source and imposes short-lived penalties.
 *
 * <p>Memory is bounded (at most {@code maxTrackedIps} entries, expired automatically) and
 * penalties always expire on their own: there is deliberately no permanent-ban mechanism here,
 * so a shared NAT address can never be banned forever by someone else's behavior. Each record
 * is guarded by its own monitor, so distinct sources never contend with each other.</p>
 */
public final class AbuseTracker {

  private final Cache<IpKey, Record> records;
  private final Ticker ticker;
  private final int threshold;
  private final long windowNanos;
  private final long penaltyNanos;

  /**
   * Creates a tracker with the system clock.
   *
   * @param threshold number of violations within the window that triggers a penalty
   * @param windowSeconds sliding window in which violations are counted
   * @param penaltySeconds duration of the penalty once triggered; {@code 0} counts only
   * @param maxTrackedIps upper bound on tracked sources
   */
  public AbuseTracker(final int threshold, final int windowSeconds, final int penaltySeconds,
      final int maxTrackedIps) {
    this(threshold, windowSeconds, penaltySeconds, maxTrackedIps, Ticker.systemTicker());
  }

  /**
   * Creates a tracker with an explicit ticker (used by tests).
   *
   * @param threshold number of violations within the window that triggers a penalty
   * @param windowSeconds sliding window in which violations are counted
   * @param penaltySeconds duration of the penalty once triggered; {@code 0} counts only
   * @param maxTrackedIps upper bound on tracked sources
   * @param ticker time source
   */
  public AbuseTracker(final int threshold, final int windowSeconds, final int penaltySeconds,
      final int maxTrackedIps, final Ticker ticker) {
    this.threshold = Math.max(1, threshold);
    this.windowNanos = TimeUnit.SECONDS.toNanos(Math.max(1, windowSeconds));
    this.penaltyNanos = TimeUnit.SECONDS.toNanos(Math.max(0, penaltySeconds));
    this.ticker = ticker;
    this.records = Caffeine.newBuilder()
        .maximumSize(Math.max(64, maxTrackedIps))
        .expireAfterWrite(Math.max(1, windowSeconds) + Math.max(0, penaltySeconds),
            TimeUnit.SECONDS)
        .build();
  }

  /**
   * Records a violation for the source of the address.
   *
   * @param address the offending address
   */
  public void recordViolation(final InetAddress address) {
    final long now = ticker.read();
    records.get(IpKey.of(address), key -> new Record()).note(now, threshold, windowNanos,
        penaltyNanos);
  }

  /**
   * Checks whether the source is currently penalized.
   *
   * @param address the address to check
   * @return {@code true} if connections from this source should be shed
   */
  public boolean isPenalized(final InetAddress address) {
    final Record record = records.getIfPresent(IpKey.of(address));
    return record != null && record.penalizedUntil(ticker.read());
  }

  /**
   * Returns the approximate number of currently tracked sources.
   *
   * @return estimated tracked source count
   */
  public long trackedSources() {
    return records.estimatedSize();
  }

  private static final class Record {

    private long windowStart = -1;
    private int count;
    private long penalizedUntil = -1;

    synchronized void note(final long now, final int threshold, final long windowNanos,
        final long penaltyNanos) {
      if (windowStart < 0 || now - windowStart >= windowNanos) {
        windowStart = now;
        count = 0;
      }
      count++;
      if (count >= threshold && penaltyNanos > 0) {
        final long until = now + penaltyNanos;
        if (until > penalizedUntil) {
          penalizedUntil = until;
        }
      }
    }

    synchronized boolean penalizedUntil(final long now) {
      return now < penalizedUntil;
    }
  }
}
