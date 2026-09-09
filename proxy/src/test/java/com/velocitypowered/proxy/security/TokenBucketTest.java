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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class TokenBucketTest {

  @Test
  void burstThenRefill() {
    final AtomicLong now = new AtomicLong(0);
    final TokenBucket bucket = TokenBucket.perSecond(10, 5, now::get);
    for (int i = 0; i < 5; i++) {
      assertTrue(bucket.tryConsume(), "burst token " + i);
    }
    assertFalse(bucket.tryConsume(), "bucket exhausted");
    now.addAndGet(TimeUnit.SECONDS.toNanos(1));
    for (int i = 0; i < 5; i++) {
      assertTrue(bucket.tryConsume(), "refilled token " + i);
    }
    assertFalse(bucket.tryConsume(), "refill is capped at burst");
  }

  @Test
  void partialRefill() {
    final AtomicLong now = new AtomicLong(0);
    final TokenBucket bucket = TokenBucket.perSecond(10, 10, now::get);
    for (int i = 0; i < 10; i++) {
      assertTrue(bucket.tryConsume());
    }
    now.addAndGet(TimeUnit.MILLISECONDS.toNanos(100));
    assertTrue(bucket.tryConsume(), "100ms at 10/s earns one token");
    assertFalse(bucket.tryConsume());
  }

  @Test
  void disabledBucketAlwaysAllows() {
    final TokenBucket bucket = TokenBucket.perSecond(0, 5);
    for (int i = 0; i < 10_000; i++) {
      assertTrue(bucket.tryConsume());
    }
  }

  @Test
  void burstBelowOneIsClamped() {
    final AtomicLong now = new AtomicLong(0);
    final TokenBucket bucket = TokenBucket.perSecond(1, 0, now::get);
    assertTrue(bucket.tryConsume());
    assertFalse(bucket.tryConsume());
  }

  @Test
  void clockGoingBackwardsGrantsNothingExtra() {
    final AtomicLong now = new AtomicLong(TimeUnit.SECONDS.toNanos(100));
    final TokenBucket bucket = TokenBucket.perSecond(10, 1, now::get);
    assertTrue(bucket.tryConsume());
    now.addAndGet(-TimeUnit.SECONDS.toNanos(50));
    assertFalse(bucket.tryConsume(), "backwards jump must not refill");
  }

  @Test
  void concurrentConsumersNeverExceedBurst() throws Exception {
    final AtomicLong now = new AtomicLong(0);
    final TokenBucket bucket = TokenBucket.perSecond(1, 1000, now::get);
    final int threads = 8;
    final int perThread = 200;
    final AtomicLong allowed = new AtomicLong();
    final CountDownLatch start = new CountDownLatch(1);
    final CountDownLatch done = new CountDownLatch(threads);
    final ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int t = 0; t < threads; t++) {
        pool.execute(() -> {
          try {
            start.await();
            for (int i = 0; i < perThread; i++) {
              if (bucket.tryConsume()) {
                allowed.incrementAndGet();
              }
            }
          } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
          } finally {
            done.countDown();
          }
        });
      }
      start.countDown();
      done.await(30, TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }
    assertEquals(1000, allowed.get(), "frozen clock: exactly the burst may be consumed");
  }
}
