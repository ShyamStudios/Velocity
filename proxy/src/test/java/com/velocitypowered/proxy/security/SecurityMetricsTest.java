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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class SecurityMetricsTest {

  @Test
  void countersArePerReason() {
    final SecurityMetrics metrics = new SecurityMetrics();
    metrics.record(SecurityMetrics.Reason.CONNECTION_RATE_LIMITED);
    metrics.record(SecurityMetrics.Reason.CONNECTION_RATE_LIMITED);
    metrics.record(SecurityMetrics.Reason.MALFORMED_PACKET);
    assertEquals(2, metrics.count(SecurityMetrics.Reason.CONNECTION_RATE_LIMITED));
    assertEquals(1, metrics.count(SecurityMetrics.Reason.MALFORMED_PACKET));
    assertEquals(0, metrics.count(SecurityMetrics.Reason.PENALIZED));
  }

  @Test
  void loggingIsGloballyThrottled() {
    final AtomicLong now = new AtomicLong(0);
    final SecurityMetrics metrics = new SecurityMetrics(now::get);
    assertTrue(metrics.record(SecurityMetrics.Reason.STATUS_RATE_LIMITED),
        "first event always logs");
    for (int i = 0; i < 1000; i++) {
      assertFalse(metrics.record(SecurityMetrics.Reason.STATUS_RATE_LIMITED),
          "flood must not produce log lines");
    }
    assertEquals(1000, metrics.suppressedLogs());
    now.addAndGet(TimeUnit.SECONDS.toNanos(11));
    assertTrue(metrics.record(SecurityMetrics.Reason.STATUS_RATE_LIMITED),
        "interval expiry re-arms logging");
  }
}
