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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.benmanes.caffeine.cache.Ticker;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class AbuseTrackerTest {

  private static final class Fixture {
    final AtomicLong now = new AtomicLong(0);
    final Ticker ticker = now::get;
    final AbuseTracker tracker = new AbuseTracker(10, 60, 30, 4096, ticker);
    final InetAddress address = InetAddress.getLoopbackAddress();
  }

  @Test
  void belowThresholdNeverPenalized() {
    final Fixture fixture = new Fixture();
    for (int i = 0; i < 9; i++) {
      fixture.tracker.recordViolation(fixture.address);
    }
    assertFalse(fixture.tracker.isPenalized(fixture.address));
  }

  @Test
  void thresholdTriggersTemporaryPenalty() {
    final Fixture fixture = new Fixture();
    for (int i = 0; i < 10; i++) {
      fixture.tracker.recordViolation(fixture.address);
    }
    assertTrue(fixture.tracker.isPenalized(fixture.address));
    fixture.now.addAndGet(TimeUnit.SECONDS.toNanos(29));
    assertTrue(fixture.tracker.isPenalized(fixture.address));
    fixture.now.addAndGet(TimeUnit.SECONDS.toNanos(2));
    assertFalse(fixture.tracker.isPenalized(fixture.address), "penalty must expire on its own");
  }

  @Test
  void windowSlides() {
    final Fixture fixture = new Fixture();
    for (int i = 0; i < 9; i++) {
      fixture.tracker.recordViolation(fixture.address);
    }
    fixture.now.addAndGet(TimeUnit.SECONDS.toNanos(61));
    fixture.tracker.recordViolation(fixture.address);
    assertFalse(fixture.tracker.isPenalized(fixture.address),
        "old violations must age out of the window");
  }

  @Test
  void zeroPenaltyOnlyCounts() {
    final AtomicLong now = new AtomicLong(0);
    final AbuseTracker tracker = new AbuseTracker(2, 60, 0, 4096, now::get);
    for (int i = 0; i < 100; i++) {
      tracker.recordViolation(InetAddress.getLoopbackAddress());
    }
    assertFalse(tracker.isPenalized(InetAddress.getLoopbackAddress()));
  }

  @Test
  void distinctSourcesAreIndependent() throws Exception {
    final Fixture fixture = new Fixture();
    for (int i = 0; i < 10; i++) {
      fixture.tracker.recordViolation(fixture.address);
    }
    assertTrue(fixture.tracker.isPenalized(fixture.address));
    assertFalse(fixture.tracker.isPenalized(InetAddress.getByName("9.9.9.9")),
        "penalizing one source must not affect another");
  }
}
