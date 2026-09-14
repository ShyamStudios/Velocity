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

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.DoubleSupplier;
import java.util.function.LongSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Watches {@link SecurityMetrics} for flood conditions and reports them.
 *
 * <p>Every {@value #POLL_SECONDS}s the monitor diffs blocked-event counters:</p>
 * <ul>
 *   <li><b>Attack start:</b> when blocked events within
 *   {@code attack-detect-window-seconds} reach {@code attack-detect-threshold}, an
 *   instant Discord alert goes out (attack type, rate, CPU + RAM).</li>
 *   <li><b>Attack end:</b> after {@code attack-end-quiet-seconds} with almost no new
 *   blocks, a summary goes out (duration, total blocked + per-type breakdown, peak
 *   block rate, CPU baseline/peak/spike, RAM heap baseline/peak/spike + system RAM).</li>
 *   <li><b>Fallback:</b> if Discord delivery fails — or no webhook is configured —
 *   the same report is saved under {@code attack-report-dir} as
 *   {@code attack-yyyyMMdd-HHmmss-<type>.json}, including the attack type.</li>
 * </ul>
 *
 * <p>All work happens on a single daemon thread; failures never affect the proxy.
 * The webhook URL itself is never logged.</p>
 */
public final class AttackMonitor {

  static final int POLL_SECONDS = 5;

  private static final Logger logger = LogManager.getLogger(AttackMonitor.class);
  private static final DateTimeFormatter FILE_STAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

  /**
   * Point-in-time memory reading. All sizes in bytes; {@code -1} means unavailable.
   */
  public static final class MemSnapshot {
    /** JVM heap currently in use, in bytes. */
    public final long heapUsed;
    /** JVM heap limit, in bytes ({@code <= 0} when unknown). */
    public final long heapMax;
    /** Physical machine memory, in bytes ({@code -1} when unavailable). */
    public final long systemTotal;
    /** Free physical machine memory, in bytes ({@code -1} when unavailable). */
    public final long systemFree;

    /**
     * Creates a memory snapshot.
     *
     * @param heapUsed bytes of JVM heap in use
     * @param heapMax bytes of JVM heap limit
     * @param systemTotal bytes of physical memory
     * @param systemFree bytes of free physical memory
     */
    public MemSnapshot(final long heapUsed, final long heapMax,
        final long systemTotal, final long systemFree) {
      this.heapUsed = heapUsed;
      this.heapMax = heapMax;
      this.systemTotal = systemTotal;
      this.systemFree = systemFree;
    }

    double heapUsedMb() {
      return heapUsed < 0 ? Double.NaN : heapUsed / 1048576.0;
    }

    double heapMaxMb() {
      return heapMax <= 0 ? Double.NaN : heapMax / 1048576.0;
    }
  }

  private final SecurityMetrics metrics;
  private volatile SecurityConfig config;
  private final DiscordWebhookSender sender;
  private final DoubleSupplier cpuSampler;
  private final java.util.function.Supplier<MemSnapshot> memSampler;
  private final LongSupplier nanoClock;
  private final LongSupplier millisClock;
  private final ScheduledExecutorService executor;
  private final boolean ownsExecutor;
  private final AtomicBoolean running = new AtomicBoolean(false);

  // Guarded by lock.
  private final Object lock = new Object();
  private final Deque<Sample> window = new ArrayDeque<>();
  private boolean inAttack;
  private long attackStartMillis;
  private long attackStartNanos;
  private EnumMap<SecurityMetrics.Reason, Long> attackStartSnapshot;
  private long attackStartTotal;
  private long lastTotal;
  private long lastCheckNanos;
  private double peakBlockedPerSecond;
  private double cpuBaseline;
  private double cpuPeak;
  private double memBaselineMb;
  private double memPeakMb;
  private MemSnapshot lastMem = null;
  private long quietNanosAccumulated;
  private double lastCpu = Double.NaN;
  private double lastMemMb = Double.NaN;
  private EnumMap<SecurityMetrics.Reason, Long> lastSnapshot;

  private static final class Sample {
    final long nanos;
    final long total;

    Sample(final long nanos, final long total) {
      this.nanos = nanos;
      this.total = total;
    }
  }

  /**
   * Creates a monitor with the production CPU sampler and clocks.
   *
   * @param metrics shared security counters
   * @param config initial security configuration
   * @param sender webhook client (URL taken from config on update)
   */
  public AttackMonitor(final SecurityMetrics metrics, final SecurityConfig config,
      final DiscordWebhookSender sender) {
    this(metrics, config, sender, AttackMonitor::sampleProcessCpu,
        AttackMonitor::sampleMemory,
        System::nanoTime, System::currentTimeMillis,
        Executors.newSingleThreadScheduledExecutor(r -> {
          final Thread thread = new Thread(r, "velocity-attack-monitor");
          thread.setDaemon(true);
          return thread;
        }), true);
  }

  AttackMonitor(final SecurityMetrics metrics, final SecurityConfig config,
      final DiscordWebhookSender sender, final DoubleSupplier cpuSampler,
      final LongSupplier nanoClock, final LongSupplier millisClock,
      final ScheduledExecutorService executor, final boolean ownsExecutor) {
    this(metrics, config, sender, cpuSampler, AttackMonitor::sampleMemory,
        nanoClock, millisClock, executor, ownsExecutor);
  }

  AttackMonitor(final SecurityMetrics metrics, final SecurityConfig config,
      final DiscordWebhookSender sender, final DoubleSupplier cpuSampler,
      final java.util.function.Supplier<MemSnapshot> memSampler,
      final LongSupplier nanoClock, final LongSupplier millisClock,
      final ScheduledExecutorService executor, final boolean ownsExecutor) {
    this.metrics = metrics;
    this.config = config;
    this.sender = sender;
    this.cpuSampler = cpuSampler;
    this.memSampler = memSampler;
    this.nanoClock = nanoClock;
    this.millisClock = millisClock;
    this.executor = executor;
    this.ownsExecutor = ownsExecutor;
    this.lastTotal = metrics.totalBlocked();
    this.lastSnapshot = metrics.snapshot();
    this.lastCheckNanos = nanoClock.getAsLong();
  }

  /**
   * Starts periodic checks.
   */
  public void start() {
    if (running.compareAndSet(false, true)) {
      sender.setWebhookUrl(config.getDiscordWebhookUrl());
      executor.scheduleAtFixedRate(this::safeCheck,
          POLL_SECONDS, POLL_SECONDS, TimeUnit.SECONDS);
      logger.info("Attack monitor started (threshold={} per {}s, quiet={}s, webhook={}).",
          config.getAttackDetectThreshold(), config.getAttackDetectWindowSeconds(),
          config.getAttackEndQuietSeconds(),
          sender.isConfigured() ? "configured" : "not configured (file fallback only)");
    }
  }

  /**
   * Applies a reloaded configuration without losing in-flight attack state.
   *
   * @param newConfig reloaded configuration
   */
  public void updateConfig(final SecurityConfig newConfig) {
    this.config = newConfig;
    sender.setWebhookUrl(newConfig.getDiscordWebhookUrl());
    synchronized (lock) {
      window.clear();
      // Re-baseline so the reload itself never trips detection.
      lastTotal = metrics.totalBlocked();
      lastSnapshot = metrics.snapshot();
    }
  }

  /**
   * Stops periodic checks.
   */
  public void shutdown() {
    if (running.compareAndSet(true, false) && ownsExecutor) {
      executor.shutdownNow();
    }
  }

  private void safeCheck() {
    try {
      check();
    } catch (final Exception e) {
      logger.warn("Attack monitor check failed.", e);
    }
  }

  /**
   * Runs one detection tick. Visible for tests.
   */
  void check() {
    final SecurityConfig current = this.config;
    final long nowNanos = nanoClock.getAsLong();
    final long nowMillis = millisClock.getAsLong();
    final long total = metrics.totalBlocked();
    final EnumMap<SecurityMetrics.Reason, Long> snapshot = metrics.snapshot();
    final double cpu = sampleCpuSafe();
    final MemSnapshot mem = sampleMemSafe();
    final double memMb = mem == null ? Double.NaN : mem.heapUsedMb();

    final long tickTotal = Math.max(0, total - lastTotal);
    final double tickSeconds = Math.max(1e-9, (nowNanos - lastCheckNanos) / 1e9);
    final double tickRate = tickTotal / tickSeconds;

    synchronized (lock) {
      // Maintain sliding detection window.
      window.addLast(new Sample(nowNanos, total));
      final long windowNanos =
          TimeUnit.SECONDS.toNanos(Math.max(1, current.getAttackDetectWindowSeconds()));
      while (window.size() > 1 && nowNanos - window.peekFirst().nanos > windowNanos) {
        window.pollFirst();
      }
      final long windowDelta = window.isEmpty() ? 0 : total - window.peekFirst().total;

      if (!inAttack) {
        cpuBaseline = rollingBaseline(cpu);
        memBaselineMb = rollingMemBaseline(memMb);
        if (mem != null) {
          lastMem = mem;
        }
        if (current.isEnabled() && windowDelta >= current.getAttackDetectThreshold()) {
          final EnumMap<SecurityMetrics.Reason, Long> tickBase =
              lastSnapshot == null ? snapshot : lastSnapshot;
          beginAttack(current, nowNanos, nowMillis, snapshot, tickBase, total, tickRate, cpu, mem);
        }
      } else {
        if (tickRate > peakBlockedPerSecond) {
          peakBlockedPerSecond = tickRate;
        }
        if (!Double.isNaN(cpu) && cpu > cpuPeak) {
          cpuPeak = cpu;
        }
        if (!Double.isNaN(memMb) && (Double.isNaN(memPeakMb) || memMb > memPeakMb)) {
          memPeakMb = memMb;
        }
        if (mem != null) {
          lastMem = mem;
        }
        // "Active" means the flood is still ongoing; otherwise accumulate quiet time.
        final double activeFloor = Math.max(2.0,
            current.getAttackDetectThreshold()
                / (double) Math.max(1, current.getAttackDetectWindowSeconds()) / 2.0);
        if (tickRate >= activeFloor) {
          quietNanosAccumulated = 0;
        } else {
          quietNanosAccumulated += (nowNanos - lastCheckNanos);
        }
        final long quietNeeded =
            TimeUnit.SECONDS.toNanos(Math.max(1, current.getAttackEndQuietSeconds()));
        if (quietNanosAccumulated >= quietNeeded) {
          endAttack(current, nowNanos, nowMillis, snapshot, total);
        }
      }
      lastTotal = total;
      lastSnapshot = new EnumMap<>(snapshot);
      lastCheckNanos = nowNanos;
      if (!Double.isNaN(cpu)) {
        lastCpu = cpu;
      }
      if (!Double.isNaN(memMb)) {
        lastMemMb = memMb;
      }
    }
  }

  private double rollingBaseline(final double cpu) {
    if (Double.isNaN(cpu)) {
      return Double.isNaN(lastCpu) ? 0.0 : lastCpu;
    }
    if (Double.isNaN(lastCpu)) {
      return cpu;
    }
    // Slow-moving baseline outside attacks; keeps spike math honest.
    return lastCpu * 0.9 + cpu * 0.1;
  }

  private double rollingMemBaseline(final double memMb) {
    if (Double.isNaN(memMb)) {
      return Double.isNaN(lastMemMb) ? 0.0 : lastMemMb;
    }
    if (Double.isNaN(lastMemMb)) {
      return memMb;
    }
    return lastMemMb * 0.9 + memMb * 0.1;
  }

  private void beginAttack(final SecurityConfig current, final long nowNanos,
      final long nowMillis, final EnumMap<SecurityMetrics.Reason, Long> snapshot,
      final EnumMap<SecurityMetrics.Reason, Long> tickBase,
      final long total, final double tickRate, final double cpu, final MemSnapshot mem) {
    inAttack = true;
    attackStartMillis = nowMillis;
    attackStartNanos = nowNanos;
    attackStartSnapshot = new EnumMap<>(snapshot);
    attackStartTotal = total;
    peakBlockedPerSecond = tickRate;
    cpuBaseline = Double.isNaN(cpu) ? (Double.isNaN(lastCpu) ? 0.0 : lastCpu) : cpu;
    cpuPeak = cpuBaseline;
    final double startMemMb = mem == null || Double.isNaN(mem.heapUsedMb())
        ? (Double.isNaN(lastMemMb) ? 0.0 : lastMemMb) : mem.heapUsedMb();
    memBaselineMb = startMemMb;
    memPeakMb = startMemMb;
    quietNanosAccumulated = 0;

    final SecurityMetrics.Reason dominant = dominantReason(tickBase, snapshot);
    final String label = attackLabel(dominant);
    logger.warn("Possible attack detected: {} ({} blocked in last {}s, {:.1f}/s, CPU {:.1f}%, RAM {:.0f} MB).",
        label, total - window.peekFirst().total, current.getAttackDetectWindowSeconds(),
        tickRate, cpuBaseline, memBaselineMb);

    if (!current.isAttackNotifyStart()) {
      return;
    }
    // Start report captures the tick that tripped detection; the end report carries
    // the full attack totals.
    final EnumMap<SecurityMetrics.Reason, Long> startFallbackTo = new EnumMap<>(snapshot);
    final MemSnapshot payloadMem = mem != null ? mem : lastMem;
    final String payload = buildStartPayload(nowMillis, dominant, label,
        total - window.peekFirst().total, tickRate, cpuBaseline,
        current.getAttackDetectWindowSeconds(), payloadMem);
    deliverOrFallback(current, payload, () -> buildStartReportFileName(nowMillis, dominant),
        () -> buildReportJson("attack_start", nowMillis, nowMillis, dominant, label,
            tickBase, startFallbackTo, tickRate, cpuBaseline, cpuBaseline,
            memBaselineMb, memBaselineMb, payloadMem, false));
  }

  private void endAttack(final SecurityConfig current, final long nowNanos,
      final long nowMillis, final EnumMap<SecurityMetrics.Reason, Long> snapshot,
      final long total) {
    final long durationSeconds = Math.max(1,
        TimeUnit.NANOSECONDS.toSeconds(Math.max(0, nowNanos - attackStartNanos)));
    final SecurityMetrics.Reason dominant = dominantReason(attackStartSnapshot, snapshot);
    final String label = attackLabel(dominant);
    final long blocked = Math.max(0, total - attackStartTotal);
    final double spike = Math.max(0.0, cpuPeak - cpuBaseline);
    final double memSpike = Math.max(0.0, memPeakMb - memBaselineMb);

    logger.warn("Attack mitigated: {} lasted {}s, blocked {} (peak {:.1f}/s, CPU spike +{:.1f}%, RAM spike +{:.0f} MB).",
        label, durationSeconds, blocked, peakBlockedPerSecond, spike, memSpike);

    inAttack = false;
    window.clear();
    quietNanosAccumulated = 0;

    final MemSnapshot endMem = lastMem;
    final String payload = buildEndPayload(attackStartMillis, nowMillis, durationSeconds,
        dominant, label, attackStartSnapshot, snapshot, blocked,
        peakBlockedPerSecond, cpuBaseline, cpuPeak, spike,
        memBaselineMb, memPeakMb, memSpike, endMem);
    final boolean shouldNotify = current.isAttackNotifyEnd();
    final String fileName = buildEndReportFileName(nowMillis, dominant);
    final String fallbackJson = buildReportJson("attack_end", attackStartMillis, nowMillis,
        dominant, label, attackStartSnapshot, snapshot, peakBlockedPerSecond,
        cpuBaseline, cpuPeak, memBaselineMb, memPeakMb, endMem, false);
    if (shouldNotify) {
      deliverOrFallback(current, payload, () -> fileName, () -> fallbackJson);
    } else {
      // Even with end-notify off, keep a local audit trail of the mitigated attack.
      writeFallbackFile(current, fileName, fallbackJson);
    }
  }

  private void deliverOrFallback(final SecurityConfig current, final String payload,
      final java.util.function.Supplier<String> fileName,
      final java.util.function.Supplier<String> fallbackJson) {
    if (!sender.isConfigured()) {
      writeFallbackFile(current, fileName.get(), fallbackJson.get());
      return;
    }
    try {
      sender.send(payload).whenComplete((ok, error) -> {
        if (error != null || !Boolean.TRUE.equals(ok)) {
          if (error != null) {
            logger.warn("Discord webhook delivery failed, saving attack report to file.", error);
          } else {
            logger.warn("Discord webhook delivery failed (no 2xx), saving attack report to file.");
          }
          writeFallbackFile(current, fileName.get(), fallbackJson.get());
        }
      });
    } catch (final Exception e) {
      logger.warn("Discord webhook delivery failed, saving attack report to file.", e);
      writeFallbackFile(current, fileName.get(), fallbackJson.get());
    }
  }

  void writeFallbackFile(final SecurityConfig current, final String fileName,
      final String json) {
    try {
      final Path dir = Path.of(current.getAttackReportDir());
      Files.createDirectories(dir);
      final Path file = dir.resolve(fileName);
      Files.writeString(file, json, StandardCharsets.UTF_8);
      logger.warn("Saved attack report to {}.", file.toAbsolutePath());
    } catch (final IOException e) {
      logger.error("Unable to save attack report file.", e);
    }
  }

  private double sampleCpuSafe() {
    try {
      final double value = cpuSampler.getAsDouble();
      if (Double.isNaN(value) || Double.isInfinite(value) || value < 0) {
        return Double.NaN;
      }
      return Math.min(100.0, value);
    } catch (final Exception e) {
      return Double.NaN;
    }
  }

  static double sampleProcessCpu() {
    try {
      final var bean = ManagementFactory.getOperatingSystemMXBean();
      if (bean instanceof com.sun.management.OperatingSystemMXBean sun) {
        final double load = sun.getProcessCpuLoad();
        if (load >= 0) {
          return load * 100.0;
        }
      }
      final double avg = bean.getSystemLoadAverage();
      if (avg >= 0) {
        return Math.min(100.0, avg * 100.0 / Math.max(1, bean.getAvailableProcessors()));
      }
    } catch (final Exception ignored) {
      // CPU telemetry is best-effort; attacks are still reported without it.
    }
    return Double.NaN;
  }

  private MemSnapshot sampleMemSafe() {
    try {
      return memSampler.get();
    } catch (final Exception e) {
      return null;
    }
  }

  static MemSnapshot sampleMemory() {
    try {
      final Runtime runtime = Runtime.getRuntime();
      final long heapUsed = runtime.totalMemory() - runtime.freeMemory();
      final long heapMax = runtime.maxMemory();
      long sysTotal = -1;
      long sysFree = -1;
      try {
        final var bean = ManagementFactory.getOperatingSystemMXBean();
        if (bean instanceof com.sun.management.OperatingSystemMXBean sun) {
          sysTotal = sun.getTotalPhysicalMemorySize();
          sysFree = sun.getFreePhysicalMemorySize();
        }
      } catch (final Exception ignored) {
        // System RAM is best-effort; heap alone is still useful.
      }
      return new MemSnapshot(heapUsed, heapMax, sysTotal, sysFree);
    } catch (final Exception e) {
      return null;
    }
  }

  static SecurityMetrics.Reason dominantReason(
      final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to) {
    SecurityMetrics.Reason best = SecurityMetrics.Reason.CONNECTION_RATE_LIMITED;
    long bestDelta = Long.MIN_VALUE;
    for (final SecurityMetrics.Reason reason : SecurityMetrics.Reason.values()) {
      final long delta = to.getOrDefault(reason, 0L) - from.getOrDefault(reason, 0L);
      if (delta > bestDelta) {
        bestDelta = delta;
        best = reason;
      }
    }
    return best;
  }

  /**
   * Human label for an attack type.
   *
   * @param reason the dominant blocked reason
   * @return short label
   */
  public static String attackLabel(final SecurityMetrics.Reason reason) {
    return switch (reason) {
      case CONNECTION_RATE_LIMITED -> "Connection Flood (new-connection rate)";
      case CONNECTION_CONCURRENT_PER_IP -> "Concurrent Connection Flood (per-IP sockets)";
      case CONNECTION_CONCURRENT_GLOBAL -> "Global Socket Exhaustion";
      case LOGIN_RATE_LIMITED -> "Login/Auth Flood";
      case STATUS_RATE_LIMITED -> "Status/Ping Flood";
      case PENALIZED -> "Repeat-Offender Flood (penalized sources)";
      case MALFORMED_PACKET -> "Malformed Packet Flood";
      case MALFORMED_BACKEND_MESSAGE -> "Backend Malformed-Message Flood";
      case BACKEND_RATE_LIMITED -> "Backend Action Flood (rate-limited)";
      case HANDSHAKE_REJECTED -> "Handshake Garbage (bad host/port)";
      case LOGIN_REPLAYED -> "Login Replay (duplicate packets)";
      case STATUS_PING_REJECTED -> "Status Ping Abuse (no request)";
      case QUERY_RATE_LIMITED -> "Query Flood (rate-limited)";
      case PROXY_SPOOFED -> "PROXY Spoof Attempt (untrusted peer)";
    };
  }

  static String buildStartPayload(final long nowMillis,
      final SecurityMetrics.Reason dominant, final String label,
      final long windowBlocked, final double rate, final double cpu,
      final int windowSeconds) {
    return buildStartPayload(nowMillis, dominant, label, windowBlocked, rate, cpu,
        windowSeconds, sampleMemory());
  }

  static String buildStartPayload(final long nowMillis,
      final SecurityMetrics.Reason dominant, final String label,
      final long windowBlocked, final double rate, final double cpu,
      final int windowSeconds, final MemSnapshot mem) {
    final String time = Instant.ofEpochMilli(nowMillis).toString();
    return "{"
        + "\"username\":\"Velocity Anti-Bot\","
        + "\"embeds\":[{"
        + "\"title\":\"\\uD83D\\uDEA8 Attack detected: " + DiscordWebhookSender.escape(label) + "\","
        + "\"description\":\"Mitigation is active — shedding hostile traffic. Summary follows when it ends.\","
        + "\"color\":15158332,"
        + "\"timestamp\":\"" + time + "\","
        + "\"fields\":["
        + field("Attack type", dominant.name() + " — " + label, false)
        + "," + field("Blocked (last " + windowSeconds + "s)", String.valueOf(windowBlocked), true)
        + "," + field("Current rate", String.format("%.1f", rate) + "/s blocked", true)
        + "," + field("Process CPU", formatCpu(cpu), true)
        + "," + field("RAM heap", formatMem(mem), true)
        + "," + field("System RAM", formatSystemMem(mem), true)
        + "]"
        + "}]"
        + "}";
  }

  static String buildEndPayload(final long startMillis, final long endMillis,
      final long durationSeconds, final SecurityMetrics.Reason dominant,
      final String label, final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to, final long totalBlocked,
      final double peakRate, final double cpuBaseline, final double cpuPeak,
      final double spike) {
    return buildEndPayload(startMillis, endMillis, durationSeconds, dominant, label,
        from, to, totalBlocked, peakRate, cpuBaseline, cpuPeak, spike,
        Double.NaN, Double.NaN, Double.NaN, sampleMemory());
  }

  static String buildEndPayload(final long startMillis, final long endMillis,
      final long durationSeconds, final SecurityMetrics.Reason dominant,
      final String label, final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to, final long totalBlocked,
      final double peakRate, final double cpuBaseline, final double cpuPeak,
      final double spike, final double memBaselineMb, final double memPeakMb,
      final double memSpikeMb, final MemSnapshot mem) {
    final String time = Instant.ofEpochMilli(endMillis).toString();
    return "{"
        + "\"username\":\"Velocity Anti-Bot\","
        + "\"embeds\":[{"
        + "\"title\":\"✅ Attack mitigated: " + DiscordWebhookSender.escape(label) + "\","
        + "\"description\":\"Blocked " + totalBlocked + " hostile events over "
        + formatDuration(durationSeconds) + ".\","
        + "\"color\":3066993,"
        + "\"timestamp\":\"" + time + "\","
        + "\"fields\":["
        + field("Attack type", dominant.name() + " — " + label, false)
        + "," + field("Duration", formatDuration(durationSeconds), true)
        + "," + field("Total blocked", String.valueOf(totalBlocked), true)
        + "," + field("Peak rate", String.format("%.1f", peakRate) + "/s blocked", true)
        + "," + field("Blocked breakdown", breakdown(from, to), false)
        + "," + field("CPU baseline", formatCpu(cpuBaseline), true)
        + "," + field("CPU peak", formatCpu(cpuPeak), true)
        + "," + field("CPU spike", "+" + String.format("%.1f", spike) + "%", true)
        + "," + field("RAM baseline", formatMb(memBaselineMb), true)
        + "," + field("RAM peak", formatMb(memPeakMb), true)
        + "," + field("RAM spike", "+" + formatMbValue(memSpikeMb), true)
        + "," + field("System RAM", formatSystemMem(mem), false)
        + "]"
        + "}]"
        + "}";
  }

  private static String field(final String name, final String value, final boolean inline) {
    String safe = value;
    if (safe.length() > 900) {
      safe = safe.substring(0, 900) + "…";
    }
    return "{\"name\":\"" + DiscordWebhookSender.escape(name) + "\","
        + "\"value\":\"" + DiscordWebhookSender.escape(safe) + "\","
        + "\"inline\":" + inline + "}";
  }

  static String breakdown(final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to) {
    final StringBuilder out = new StringBuilder();
    for (final SecurityMetrics.Reason reason : SecurityMetrics.Reason.values()) {
      final long delta = to.getOrDefault(reason, 0L) - from.getOrDefault(reason, 0L);
      if (delta > 0) {
        if (out.length() > 0) {
          out.append('\n');
        }
        out.append(reason.name()).append(": ").append(delta);
      }
    }
    return out.length() == 0 ? "none" : out.toString();
  }

  static String buildReportJson(final String event, final long startMillis,
      final long endMillis, final SecurityMetrics.Reason dominant, final String label,
      final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to,
      final double peakRate, final double cpuBaseline, final double cpuPeak,
      final boolean webhookDelivered) {
    return buildReportJson(event, startMillis, endMillis, dominant, label, from, to,
        peakRate, cpuBaseline, cpuPeak, Double.NaN, Double.NaN, null, webhookDelivered);
  }

  static String buildReportJson(final String event, final long startMillis,
      final long endMillis, final SecurityMetrics.Reason dominant, final String label,
      final EnumMap<SecurityMetrics.Reason, Long> from,
      final EnumMap<SecurityMetrics.Reason, Long> to,
      final double peakRate, final double cpuBaseline, final double cpuPeak,
      final double memBaselineMb, final double memPeakMb, final MemSnapshot mem,
      final boolean webhookDelivered) {
    final long total = nullToZero(to) - nullToZero(from);
    final StringBuilder perReason = new StringBuilder("{");
    boolean first = true;
    for (final SecurityMetrics.Reason reason : SecurityMetrics.Reason.values()) {
      final long delta = to.getOrDefault(reason, 0L) - from.getOrDefault(reason, 0L);
      if (!first) {
        perReason.append(",");
      }
      perReason.append("\"").append(reason.name()).append("\":").append(Math.max(0, delta));
      first = false;
    }
    perReason.append("}");
    final long durationSeconds = Math.max(0, (endMillis - startMillis) / 1000);
    final double memSpike = (Double.isNaN(memBaselineMb) || Double.isNaN(memPeakMb))
        ? Double.NaN : Math.max(0.0, memPeakMb - memBaselineMb);
    final String heapMaxJson = mem == null || Double.isNaN(mem.heapMaxMb())
        ? "null" : String.format("%.2f", mem.heapMaxMb());
    final String sysTotalJson = mem == null || mem.systemTotal <= 0
        ? "null" : String.valueOf(mem.systemTotal);
    final String sysFreeJson = mem == null || mem.systemFree < 0
        ? "null" : String.valueOf(mem.systemFree);
    return "{"
        + "\"event\":\"" + event + "\","
        + "\"attackType\":\"" + dominant.name() + "\","
        + "\"attackLabel\":\"" + DiscordWebhookSender.escape(label) + "\","
        + "\"startedAt\":\"" + Instant.ofEpochMilli(startMillis) + "\","
        + "\"endedAt\":\"" + Instant.ofEpochMilli(endMillis) + "\","
        + "\"durationSeconds\":" + durationSeconds + ","
        + "\"totalBlocked\":" + Math.max(0, total) + ","
        + "\"blockedByReason\":" + perReason + ","
        + "\"peakBlockedPerSecond\":" + String.format("%.2f", peakRate) + ","
        + "\"cpuBaselinePercent\":" + formatJsonDouble(cpuBaseline) + ","
        + "\"cpuPeakPercent\":" + formatJsonDouble(cpuPeak) + ","
        + "\"cpuSpikePercent\":" + formatJsonDouble(Math.max(0.0, cpuPeak - cpuBaseline)) + ","
        + "\"ramBaselineMb\":" + formatJsonDouble(memBaselineMb) + ","
        + "\"ramPeakMb\":" + formatJsonDouble(memPeakMb) + ","
        + "\"ramSpikeMb\":" + formatJsonDouble(memSpike) + ","
        + "\"heapMaxMb\":" + heapMaxJson + ","
        + "\"systemTotalBytes\":" + sysTotalJson + ","
        + "\"systemFreeBytes\":" + sysFreeJson + ","
        + "\"webhookDelivered\":" + webhookDelivered
        + "}";
  }

  private static long nullToZero(final EnumMap<SecurityMetrics.Reason, Long> map) {
    long total = 0;
    for (final long value : map.values()) {
      total += value;
    }
    return total;
  }

  private static String formatJsonDouble(final double value) {
    if (Double.isNaN(value) || Double.isInfinite(value)) {
      return "null";
    }
    return String.format("%.2f", value);
  }

  static String formatCpu(final double cpu) {
    if (Double.isNaN(cpu) || Double.isInfinite(cpu)) {
      return "n/a";
    }
    return String.format("%.1f", cpu) + "%";
  }

  static String formatMb(final double mb) {
    if (Double.isNaN(mb) || Double.isInfinite(mb)) {
      return "n/a";
    }
    return String.format("%.0f MB", mb);
  }

  private static String formatMbValue(final double mb) {
    if (Double.isNaN(mb) || Double.isInfinite(mb)) {
      return "n/a";
    }
    return String.format("%.0f MB", mb);
  }

  static String formatMem(final MemSnapshot mem) {
    if (mem == null || Double.isNaN(mem.heapUsedMb())) {
      return "n/a";
    }
    if (Double.isNaN(mem.heapMaxMb())) {
      return String.format("%.0f MB", mem.heapUsedMb());
    }
    final double pct = mem.heapMaxMb() <= 0 ? 0 : mem.heapUsedMb() * 100.0 / mem.heapMaxMb();
    return String.format("%.0f/%.0f MB (%.0f%%)", mem.heapUsedMb(), mem.heapMaxMb(), pct);
  }

  static String formatSystemMem(final MemSnapshot mem) {
    if (mem == null || mem.systemTotal <= 0 || mem.systemFree < 0) {
      return "n/a";
    }
    final double totalGb = mem.systemTotal / 1073741824.0;
    final double usedGb = (mem.systemTotal - mem.systemFree) / 1073741824.0;
    final double pct = mem.systemTotal <= 0
        ? 0 : (mem.systemTotal - mem.systemFree) * 100.0 / mem.systemTotal;
    return String.format("%.1f/%.1f GB (%.0f%%)", usedGb, totalGb, pct);
  }

  static String formatDuration(final long seconds) {
    if (seconds < 60) {
      return seconds + "s";
    }
    final long minutes = seconds / 60;
    final long rest = seconds % 60;
    if (minutes < 60) {
      return minutes + "m " + rest + "s";
    }
    return (minutes / 60) + "h " + (minutes % 60) + "m " + rest + "s";
  }

  static String buildStartReportFileName(final long nowMillis,
      final SecurityMetrics.Reason dominant) {
    return "attack-" + stamp(nowMillis) + "-" + dominant.name() + "-start.json";
  }

  static String buildEndReportFileName(final long nowMillis,
      final SecurityMetrics.Reason dominant) {
    return "attack-" + stamp(nowMillis) + "-" + dominant.name() + ".json";
  }

  private static String stamp(final long millis) {
    return LocalDateTime.ofInstant(Instant.ofEpochMilli(millis), ZoneId.systemDefault())
        .format(FILE_STAMP);
  }

  /**
   * Returns whether an attack is currently considered ongoing (for tests/diagnostics).
   *
   * @return {@code true} inside an attack
   */
  boolean isInAttack() {
    synchronized (lock) {
      return inAttack;
    }
  }
}
