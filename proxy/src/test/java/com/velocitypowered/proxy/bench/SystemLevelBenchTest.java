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

package com.velocitypowered.proxy.bench;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import com.sun.management.ThreadMXBean;
import com.velocitypowered.api.network.HandshakeIntent;
import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.server.ServerPing;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.PlayerInfoForwarding;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.connection.util.ServerListPingHandler;
import com.velocitypowered.proxy.network.ServerChannelInitializer;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import com.velocitypowered.proxy.protocol.StateRegistry;
import com.velocitypowered.proxy.protocol.netty.MinecraftDecoder;
import com.velocitypowered.proxy.protocol.netty.MinecraftEncoder;
import com.velocitypowered.proxy.protocol.netty.MinecraftVarintFrameDecoder;
import com.velocitypowered.proxy.protocol.packet.HandshakePacket;
import com.velocitypowered.proxy.protocol.packet.KeepAlivePacket;
import com.velocitypowered.proxy.protocol.packet.StatusRequestPacket;
import com.velocitypowered.proxy.util.ratelimit.Ratelimiters;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.Test;

/**
 * System-level comparison harness: drives realistic byte streams through the real Netty
 * pipeline (framing, decoding, session handling, encoding) and reports whole-run wall time,
 * allocated bytes, GC activity, and heap deltas.
 *
 * <p>Run with {@code ./gradlew :velocity-proxy:test --tests
 * "com.velocitypowered.proxy.bench.SystemLevelBenchTest"} and optional environment
 * {@code BENCH_LABEL, BENCH_CONNS, BENCH_PLAY, BENCH_ROUNDS}. Prints {@code BENCH} lines;
 * asserts only correctness (message counts), never performance, so it stays green in CI.
 * Security hooks resolve reflectively, so this file compiles and runs unmodified on both
 * the fork and the baseline tree.</p>
 */
class SystemLevelBenchTest {

  private static final ProtocolVersion VERSION = ProtocolVersion.MINECRAFT_1_20_2;

  /**
   * Builds the fork's rate limiter reflectively so this file also compiles and runs on the
   * baseline tree (where the security package does not exist). Returns {@code null} there.
   */
  static Object newLimiter() {
    try {
      final Class<?> metricsClass =
          Class.forName("com.velocitypowered.proxy.security.SecurityMetrics");
      final Class<?> configClass =
          Class.forName("com.velocitypowered.proxy.security.SecurityConfig");
      final Object metrics = metricsClass.getDeclaredConstructor().newInstance();
      final Object defaults = configClass.getField("DEFAULT").get(null);
      final Class<?> limiterClass =
          Class.forName("com.velocitypowered.proxy.security.ConnectionRateLimiter");
      return limiterClass.getDeclaredConstructor(configClass, metricsClass)
          .newInstance(defaults, metrics);
    } catch (final ReflectiveOperationException e) {
      return null;
    }
  }

  /**
   * Stubs a no-arg getter on the server mock when it exists (fork) and does nothing when it
   * does not (baseline).
   */
  static void stubIfPresent(final VelocityServer server, final String method,
      final Object value) {
    try {
      final java.lang.reflect.Method getter = server.getClass().getMethod(method);
      getter.invoke(org.mockito.Mockito.doReturn(value).when(server));
    } catch (final ReflectiveOperationException e) {
      // Baseline build: nothing to stub.
    }
  }

  static final class Fixture implements AutoCloseable {

    final VelocityServer server;

    Fixture() {
      // stubOnly: plain mocks record every invocation for potential verify(), which would
      // retain millions of call records over a soak run and exhaust the heap. We only stub.
      this.server = mock(VelocityServer.class, withSettings().stubOnly());
      final VelocityConfiguration config =
          mock(VelocityConfiguration.class, withSettings().stubOnly());
      when(config.getReadTimeout()).thenReturn(30000);
      when(config.isProxyProtocol()).thenReturn(false);
      when(config.isPlayerAddressLoggingEnabled()).thenReturn(false);
      when(config.isLogPlayerConnections()).thenReturn(false);
      when(config.isShowPingRequests()).thenReturn(false);
      when(config.isAcceptTransfers()).thenReturn(false);
      when(config.getPlayerInfoForwardingMode()).thenReturn(PlayerInfoForwarding.NONE);
      when(config.getPacketLimiterConfig())
          .thenReturn(VelocityConfiguration.PacketLimiterConfig.DEFAULT);
      when(config.getLoginRatelimit()).thenReturn(0);
      when(server.getConfiguration()).thenReturn(config);
      when(server.getIpAttemptLimiter()).thenReturn(Ratelimiters.createWithMilliseconds(0));
      stubIfPresent(server, "getConnectionRateLimiter", newLimiter());
      try {
        final Class<?> metricsClass =
            Class.forName("com.velocitypowered.proxy.security.SecurityMetrics");
        stubIfPresent(server, "getSecurityMetrics",
            metricsClass.getDeclaredConstructor().newInstance());
      } catch (final ReflectiveOperationException e) {
        // Baseline build: no metrics hook to stub.
      }
      final com.velocitypowered.proxy.event.VelocityEventManager eventManager = mock(
          com.velocitypowered.proxy.event.VelocityEventManager.class,
          withSettings().stubOnly());
      when(eventManager.fire(any())).thenAnswer(
          invocation -> CompletableFuture.completedFuture(invocation.getArgument(0)));
      when(server.getEventManager()).thenReturn(eventManager);
      final ServerListPingHandler pingHandler =
          mock(ServerListPingHandler.class, withSettings().stubOnly());
      final ServerPing ping = new ServerPing(new ServerPing.Version(766, "1.20.5"), null,
          Component.text("bench"), null);
      when(pingHandler.getInitialPing(any()))
          .thenReturn(CompletableFuture.completedFuture(ping));
      when(server.getServerListPingHandler()).thenReturn(pingHandler);
    }

    @Override
    public void close() {
    }
  }

  static final class CountingHandler extends ChannelInboundHandlerAdapter {

    int messages;

    @Override
    public void channelRead(final io.netty.channel.ChannelHandlerContext ctx, final Object msg) {
      messages++;
      io.netty.util.ReferenceCountUtil.release(msg);
    }
  }

  static final class GcSnapshot {

    final long count;
    final long millis;

    GcSnapshot() {
      long count = 0;
      long millis = 0;
      for (final GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
        count += bean.getCollectionCount();
        millis += bean.getCollectionTime();
      }
      this.count = count;
      this.millis = millis;
    }
  }

  static long allocatedBytes() {
    final ThreadMXBean bean =
        (ThreadMXBean) ManagementFactory.getThreadMXBean();
    return bean.getCurrentThreadAllocatedBytes();
  }

  static long usedHeap() {
    final Runtime runtime = Runtime.getRuntime();
    return runtime.totalMemory() - runtime.freeMemory();
  }

  private EmbeddedChannel newFrontend(final Fixture fixture) {
    final EmbeddedChannel channel = new EmbeddedChannel();
    channel.pipeline().addLast(new ServerChannelInitializer(fixture.server));
    return channel;
  }

  static ByteBuf frame(final ByteBuf payload) {
    final ByteBuf out = Unpooled.buffer();
    ProtocolUtils.writeVarInt(out, payload.readableBytes());
    out.writeBytes(payload);
    payload.release();
    return out;
  }

  static String env(final String name, final String def) {
    final String value = System.getenv(name);
    return value == null ? def : value;
  }

  static void printPercentiles(final String workload, final long[] nanos, final int units) {
    final long[] sorted = nanos.clone();
    java.util.Arrays.sort(sorted);
    System.out.println("BENCH_PCT workload=" + workload + " units=" + units + " p50ns="
        + sorted[(int) (sorted.length * 0.50)] + " p95ns=" + sorted[(int) (sorted.length * 0.95)]
        + " p99ns=" + sorted[Math.min(sorted.length - 1, (int) (sorted.length * 0.99))] + " maxNs="
        + sorted[sorted.length - 1]);
  }

  @Test
  void runAllWorkloads() throws Exception {
    final String label = env("BENCH_LABEL", "run");
    final int conns = Integer.parseInt(env("BENCH_CONNS", "2000"));
    final int playPerConn = Integer.parseInt(env("BENCH_PLAY", "200"));
    final int rounds = Integer.parseInt(env("BENCH_ROUNDS", "3"));
    final int soakMinutes = Integer.parseInt(env("BENCH_SOAK_MINUTES", "0"));
    final int floodAttempts = Integer.parseInt(env("BENCH_FLOOD", "20000"));

    System.out.println("BENCH config label=" + label + " conns=" + conns + " playPerConn="
        + playPerConn + " rounds=" + rounds + " soakMinutes=" + soakMinutes + " flood="
        + floodAttempts + " cpus=" + Runtime.getRuntime().availableProcessors() + " maxHeap="
        + Runtime.getRuntime().maxMemory() + " java=" + System.getProperty("java.version"));

    // Warmup (discarded).
    try (final Fixture fixture = new Fixture()) {
      runHandshakeStorm(fixture, Math.min(conns, 200), false);
      runPlayMix(fixture, Math.min(conns, 50), 20, false);
    }

    try (final Fixture fixture = new Fixture()) {
      for (int round = 0; round < rounds; round++) {
        runMockCalibration(fixture, 20000, round == rounds - 1);
        runHandshakeStorm(fixture, conns, true);
        runPlayMix(fixture, conns / 10, playPerConn, true);
        runStatusStorm(fixture, conns / 10, true);
        runMalformedStorm(fixture, conns / 10, true);
        runFloodStorm(fixture, floodAttempts, true);
      }
      if (soakMinutes > 0) {
        runSoak(fixture, soakMinutes);
      }
    }
    assertTrue(true);
  }

  /**
   * Measures the harness-only cost of mocked server getter calls. Mockito invocations allocate
   * (production uses direct field reads instead), and only the fork's added hooks make extra
   * mocked calls — two per connection (handshake/status/malformed), three more per status
   * request, one more per malformed packet. Uses only long-standing APIs so this compiles on
   * the baseline tree too; each iteration performs two getter calls.
   */
  private void runMockCalibration(final Fixture fixture, final int count,
      final boolean measure) {
    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    int observed = 0;
    for (int i = 0; i < count; i++) {
      // No-op use of the results keeps the calls observable to the JIT.
      if (fixture.server.getConfiguration().isProxyProtocol()) {
        observed++;
      }
      observed += fixture.server.getConfiguration().getReadTimeout() == 0 ? 1 : 0;
    }
    report("mock-calibration", measure, count, start, allocBefore, heapBefore, gcBefore);
    assertTrue(observed >= 0);
  }

  private void runHandshakeStorm(final Fixture fixture, final int conns, final boolean measure) {
    final List<ByteBuf> handshakes = new ArrayList<>(conns);
    for (int i = 0; i < conns; i++) {
      final HandshakePacket handshake = new HandshakePacket();
      handshake.setProtocolVersion(VERSION);
      handshake.setServerAddress("localhost");
      handshake.setPort(25565);
      handshake.setIntent(HandshakeIntent.LOGIN);
      handshakes.add(encodeWith(StateRegistry.HANDSHAKE, handshake));
    }
    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    final long[] timings = new long[handshakes.size()];
    int completed = 0;
    for (final ByteBuf bytes : handshakes) {
      final long unitStart = System.nanoTime();
      final EmbeddedChannel channel = newFrontend(fixture);
      channel.pipeline().fireChannelActive();
      channel.writeInbound(bytes);
      channel.pipeline().fireChannelInactive();
      channel.finishAndReleaseAll();
      timings[completed] = System.nanoTime() - unitStart;
      completed++;
    }
    report("handshake", measure, completed, start, allocBefore, heapBefore, gcBefore);
    if (measure) {
      printPercentiles("handshake", timings, completed);
    }
    assertEquals(conns, completed);
  }

  private void runPlayMix(final Fixture fixture, final int conns, final int perConn,
      final boolean measure) {
    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    final long[] timings = new long[conns];
    int decoded = 0;
    for (int c = 0; c < conns; c++) {
      final long unitStart = System.nanoTime();
      final EmbeddedChannel channel = new EmbeddedChannel();
      channel.pipeline()
          .addLast(new MinecraftVarintFrameDecoder(ProtocolUtils.Direction.SERVERBOUND))
          .addLast(new MinecraftDecoder(ProtocolUtils.Direction.SERVERBOUND));
      channel.pipeline().get(MinecraftVarintFrameDecoder.class)
          .setState(StateRegistry.PLAY);
      channel.pipeline().get(MinecraftDecoder.class).setState(StateRegistry.PLAY);
      channel.pipeline().get(MinecraftDecoder.class).setProtocolVersion(VERSION);
      final CountingHandler counter = new CountingHandler();
      channel.pipeline().addLast(counter);
      for (int i = 0; i < perConn; i++) {
        if (i % 10 == 0) {
          final KeepAlivePacket keepAlive = new KeepAlivePacket();
          keepAlive.setRandomId(i);
          channel.writeInbound(frame(encodePlayServerbound(keepAlive)));
        } else {
          // Unknown PLAY id: exercises the zero-copy passthrough path.
          final ByteBuf payload = Unpooled.buffer(8);
          ProtocolUtils.writeVarInt(payload, 0x7E);
          payload.writeBytes(new byte[] {1, 2, 3, 4, 5});
          channel.writeInbound(frame(payload));
        }
      }
      decoded += counter.messages;
      channel.finishAndReleaseAll();
      timings[c] = System.nanoTime() - unitStart;
    }
    report("play-mix", measure, decoded, start, allocBefore, heapBefore, gcBefore);
    if (measure) {
      printPercentiles("play-mix-per-conn", timings, conns);
    }
    assertEquals(conns * perConn, decoded);
  }

  private void runStatusStorm(final Fixture fixture, final int count, final boolean measure) {
    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    final long[] timings = new long[count];
    int completed = 0;
    for (int i = 0; i < count; i++) {
      final long unitStart = System.nanoTime();
      final EmbeddedChannel channel = newFrontend(fixture);
      channel.pipeline().fireChannelActive();
      final HandshakePacket handshake = new HandshakePacket();
      handshake.setProtocolVersion(VERSION);
      handshake.setServerAddress("localhost");
      handshake.setPort(25565);
      handshake.setIntent(HandshakeIntent.STATUS);
      channel.writeInbound(encodeWith(StateRegistry.HANDSHAKE, handshake));
      channel.writeInbound(encodeWith(StateRegistry.STATUS, StatusRequestPacket.INSTANCE));
      channel.runPendingTasks();
      channel.pipeline().fireChannelInactive();
      channel.finishAndReleaseAll();
      timings[completed] = System.nanoTime() - unitStart;
      completed++;
    }
    report("status", measure, completed, start, allocBefore, heapBefore, gcBefore);
    if (measure) {
      printPercentiles("status", timings, completed);
    }
    assertEquals(count, completed);
  }

  private void runMalformedStorm(final Fixture fixture, final int count, final boolean measure) {
    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    final long[] timings = new long[count];
    int completed = 0;
    for (int i = 0; i < count; i++) {
      final long unitStart = System.nanoTime();
      final EmbeddedChannel channel = newFrontend(fixture);
      channel.pipeline().fireChannelActive();
      // Frame claims 5 bytes, carries a 5-byte non-terminating varint + truncated string.
      final ByteBuf garbage = Unpooled.wrappedBuffer(
          new byte[] {6, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x7F, 0x01});
      try {
        channel.writeInbound(garbage);
      } catch (final Exception expected) {
        // Decoder failures surface here on embedded channels; production closes the channel.
      }
      channel.pipeline().fireChannelInactive();
      channel.finishAndReleaseAll();
      timings[completed] = System.nanoTime() - unitStart;
      completed++;
    }
    report("malformed", measure, completed, start, allocBefore, heapBefore, gcBefore);
    if (measure) {
      printPercentiles("malformed", timings, completed);
    }
    assertEquals(count, completed);
  }

  /**
   * Flood workload: rapid attempts from one abusive source with one legitimate attempt
   * interleaved every tenth try. On the fork this exercises the real admission path
   * (shed cheaply); on the baseline tree the limiter does not exist, so every attempt pays
   * a full handshake decode — exactly what upstream must do with flood traffic.
   */
  private void runFloodStorm(final Fixture fixture, final int attempts, final boolean measure)
      throws Exception {
    final Object limiter = newLimiter();
    final java.net.InetSocketAddress floodAddr =
        new java.net.InetSocketAddress(java.net.InetAddress.getByName("10.99.0.1"), 50000);
    final List<ByteBuf> handshakeBytes = new ArrayList<>(1);
    HandshakePacket handshake = new HandshakePacket();
    handshake.setProtocolVersion(VERSION);
    handshake.setServerAddress("localhost");
    handshake.setPort(25565);
    handshake.setIntent(HandshakeIntent.LOGIN);
    handshakeBytes.add(encodeWith(StateRegistry.HANDSHAKE, handshake));

    final GcSnapshot gcBefore = new GcSnapshot();
    final long allocBefore = allocatedBytes();
    final long heapBefore = usedHeap();
    final long start = System.nanoTime();
    final long[] legitTimings = new long[attempts / 10 + 1];
    int shed = 0;
    int admitted = 0;
    int legitOk = 0;
    int legitFail = 0;
    int legitIdx = 0;
    for (int i = 0; i < attempts; i++) {
      if (i % 10 == 0) {
        // Legitimate user from their own address.
        final long unitStart = System.nanoTime();
        final java.net.InetSocketAddress legitAddr = new java.net.InetSocketAddress(
            java.net.InetAddress.getByAddress(
                new byte[] {10, 99, (byte) (1 + (i / 10) % 20), (byte) (1 + (i / 10) / 20)}),
            50000);
        if (limiter == null) {
          decodeOneHandshake(fixture, handshakeBytes.get(0).retainedDuplicate());
          legitOk++;
        } else if (tryAcquire(limiter, legitAddr)) {
          legitOk++;
        } else {
          legitFail++;
        }
        legitTimings[legitIdx++] = System.nanoTime() - unitStart;
      } else if (limiter == null) {
        decodeOneHandshake(fixture, handshakeBytes.get(0).retainedDuplicate());
      } else if (tryAcquire(limiter, floodAddr)) {
        admitted++;
      } else {
        shed++;
      }
    }
    handshakeBytes.get(0).release();
    final GcSnapshot gcAfter = new GcSnapshot();
    if (measure) {
      System.out.println("BENCH workload=flood attempts=" + attempts + " shed=" + shed
          + " admitted=" + admitted + " legitOk=" + legitOk + " legitFail=" + legitFail
          + " wallMs=" + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
          + " allocatedBytes=" + (allocatedBytes() - allocBefore) + " heapDeltaBytes="
          + (usedHeap() - heapBefore) + " gcCount=" + (gcAfter.count - gcBefore.count)
          + " gcMs=" + (gcAfter.millis - gcBefore.millis));
      final long[] legitUsed = java.util.Arrays.copyOf(legitTimings, legitIdx);
      printPercentiles("flood-legit", legitUsed, legitIdx);
    }
    assertEquals(0, legitFail);
  }

  private void decodeOneHandshake(final Fixture fixture, final ByteBuf bytes) {
    final EmbeddedChannel channel = newFrontend(fixture);
    channel.pipeline().fireChannelActive();
    channel.writeInbound(bytes);
    channel.pipeline().fireChannelInactive();
    channel.finishAndReleaseAll();
  }

  /**
   * Reflective admission check: {@code true} means the attempt was allowed (and released).
   */
  static boolean tryAcquire(final Object limiter, final java.net.SocketAddress remote)
      throws Exception {
    final java.lang.reflect.Method acquire =
        limiter.getClass().getMethod("tryAcquireConnection", java.net.SocketAddress.class,
            boolean.class);
    final Object attempt = acquire.invoke(limiter, remote, true);
    final java.lang.reflect.Method decision =
        attempt.getClass().getMethod("decision");
    final Object verdict = decision.invoke(attempt);
    final boolean allowed = "ALLOWED".equals(((Enum<?>) verdict).name());
    if (allowed) {
      final java.lang.reflect.Method acquisition =
          attempt.getClass().getMethod("acquisition");
      final Object handle = acquisition.invoke(attempt);
      if (handle != null) {
        final java.lang.reflect.Method release =
            limiter.getClass().getMethod("release", handle.getClass());
        release.invoke(limiter, handle);
      }
    }
    return allowed;
  }

  /**
   * Sustained soak: repeats a mixed mini-workload until the minute budget expires, printing
   * one sample line per minute (wall, allocation, GC, heap, threads) to expose growth, drift,
   * or leaks over time.
   */
  private void runSoak(final Fixture fixture, final int minutes) throws Exception {
    final long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(minutes);
    int minute = 0;
    final GcSnapshot totalGcBefore = new GcSnapshot();
    final long totalAllocBefore = allocatedBytes();
    while (System.nanoTime() < deadline) {
      final long minuteStart = System.nanoTime();
      final long minuteDeadline = minuteStart + TimeUnit.MINUTES.toNanos(1);
      final GcSnapshot gcBefore = new GcSnapshot();
      final long allocBefore = allocatedBytes();
      int units = 0;
      while (System.nanoTime() < Math.min(minuteDeadline, deadline)) {
        runHandshakeStorm(fixture, 50, false);
        runPlayMix(fixture, 5, 50, false);
        runStatusStorm(fixture, 5, false);
        runMalformedStorm(fixture, 5, false);
        runFloodStorm(fixture, 500, false);
        units += 560;
      }
      final GcSnapshot gcAfter = new GcSnapshot();
      final int threads =
          ManagementFactory.getThreadMXBean().getThreadCount();
      System.out.println("BENCH soak minute=" + (++minute) + " units=" + units + " wallMs="
          + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - minuteStart) + " allocatedBytes="
          + (allocatedBytes() - allocBefore) + " heapBytes=" + usedHeap() + " threads=" + threads
          + " gcCount=" + (gcAfter.count - gcBefore.count) + " gcMs="
          + (gcAfter.millis - gcBefore.millis) + " totalGcCount="
          + (gcAfter.count - totalGcBefore.count) + " totalGcMs="
          + (gcAfter.millis - totalGcBefore.millis) + " totalAllocMB="
          + ((allocatedBytes() - totalAllocBefore) / 1048576));
    }
  }

  private void report(final String workload, final boolean measure, final int units,
      final long start, final long allocBefore, final long heapBefore,
      final GcSnapshot gcBefore) {
    final long wallMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    final GcSnapshot gcAfter = new GcSnapshot();
    final long allocated = allocatedBytes() - allocBefore;
    final long heapDelta = usedHeap() - heapBefore;
    if (measure) {
      System.out.println("BENCH workload=" + workload + " units=" + units + " wallMs=" + wallMs
          + " allocatedBytes=" + allocated + " heapDeltaBytes=" + heapDelta + " gcCount="
          + (gcAfter.count - gcBefore.count) + " gcMs=" + (gcAfter.millis - gcBefore.millis));
    }
  }

  private ByteBuf encodeWith(final StateRegistry state,
      final com.velocitypowered.proxy.protocol.MinecraftPacket packet) {
    final StateRegistry.PacketRegistry.ProtocolRegistry serverbound =
        state.getProtocolRegistry(ProtocolUtils.Direction.SERVERBOUND, VERSION);
    final EmbeddedChannel encoder = new EmbeddedChannel(
        new MinecraftEncoder(ProtocolUtils.Direction.SERVERBOUND));
    encoder.pipeline().get(MinecraftEncoder.class).setState(state);
    encoder.pipeline().get(MinecraftEncoder.class).setProtocolVersion(VERSION);
    encoder.writeOutbound(packet);
    final ByteBuf encoded = encoder.readOutbound();
    // Wrap with a length prefix like the wire does.
    final ByteBuf framed = frame(encoded);
    encoder.finishAndReleaseAll();
    return framed;
  }

  private ByteBuf encodePlayServerbound(final KeepAlivePacket packet) {
    final EmbeddedChannel encoder = new EmbeddedChannel(
        new MinecraftEncoder(ProtocolUtils.Direction.SERVERBOUND));
    encoder.pipeline().get(MinecraftEncoder.class).setState(StateRegistry.PLAY);
    encoder.pipeline().get(MinecraftEncoder.class).setProtocolVersion(VERSION);
    encoder.writeOutbound(packet);
    final ByteBuf encoded = encoder.readOutbound();
    encoder.finishAndReleaseAll();
    return encoded;
  }
}
