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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Connection-abuse protections, configured via a standalone {@code secure.yml} kept next to
 * {@code velocity.toml}.
 *
 * <p>Every limit follows the same convention: {@code 0} disables that individual check. All
 * defaults are deliberately lenient toward legitimate traffic — a normal player, household, or
 * small LAN party will never trip them — while still shedding floods and scanners. See
 * {@code SECURITY.md} and the comments in {@code default-secure.yml} for the rationale behind
 * each default.</p>
 */
public final class SecurityConfig {

  private static final Logger logger = LogManager.getLogger(SecurityConfig.class);

  /** File name of the security configuration in the working directory. */
  public static final String FILE_NAME = "secure.yml";

  /** Classpath resource used to create {@link #FILE_NAME} on first boot. */
  public static final String DEFAULT_RESOURCE = "/default-secure.yml";

  /** Default configuration, used when {@code secure.yml} is absent or empty. */
  public static final SecurityConfig DEFAULT = new SecurityConfig(
      true, 32, 10, 20, 50000, 0, 2, 4, 5, 10, 10, 60, 30,
      "", true, true, 100, 30, 60, "attack-reports");

  private final boolean enabled;
  private final int maxConcurrentConnectionsPerIp;
  private final int maxNewConnectionsPerSecondPerIp;
  private final int newConnectionsBurstPerIp;
  private final int maxConcurrentConnectionsGlobal;
  private final int maxNewConnectionsPerSecondGlobal;
  private final int maxLoginAttemptsPerSecondPerIp;
  private final int loginAttemptsBurstPerIp;
  private final int maxStatusRequestsPerSecondPerIp;
  private final int statusRequestsBurstPerIp;
  private final int abuseThreshold;
  private final int abuseWindowSeconds;
  private final int abusePenaltySeconds;
  private final String discordWebhookUrl;
  private final boolean attackNotifyStart;
  private final boolean attackNotifyEnd;
  private final int attackDetectThreshold;
  private final int attackDetectWindowSeconds;
  private final int attackEndQuietSeconds;
  private final String attackReportDir;

  /**
   * Creates a configuration with explicit values.
   *
   * @param enabled master switch for connection-abuse protections
   * @param maxConcurrentConnectionsPerIp simultaneous connections per source ({@code <= 0} disables)
   * @param maxNewConnectionsPerSecondPerIp sustained new connections per source ({@code <= 0} disables)
   * @param newConnectionsBurstPerIp burst allowance for new connections
   * @param maxConcurrentConnectionsGlobal simultaneous connections proxy-wide ({@code <= 0} disables)
   * @param maxNewConnectionsPerSecondGlobal sustained new connections proxy-wide ({@code <= 0} disables)
   * @param maxLoginAttemptsPerSecondPerIp sustained login attempts per source ({@code <= 0} disables)
   * @param loginAttemptsBurstPerIp burst allowance for login attempts
   * @param maxStatusRequestsPerSecondPerIp sustained status requests per source ({@code <= 0} disables)
   * @param statusRequestsBurstPerIp burst allowance for status requests
   * @param abuseThreshold violations within the window that trigger a temporary penalty
   * @param abuseWindowSeconds window in which violations are counted
   * @param abusePenaltySeconds penalty duration ({@code 0} counts without penalizing)
   */
  public SecurityConfig(final boolean enabled,
      final int maxConcurrentConnectionsPerIp,
      final int maxNewConnectionsPerSecondPerIp,
      final int newConnectionsBurstPerIp,
      final int maxConcurrentConnectionsGlobal,
      final int maxNewConnectionsPerSecondGlobal,
      final int maxLoginAttemptsPerSecondPerIp,
      final int loginAttemptsBurstPerIp,
      final int maxStatusRequestsPerSecondPerIp,
      final int statusRequestsBurstPerIp,
      final int abuseThreshold,
      final int abuseWindowSeconds,
      final int abusePenaltySeconds) {
    this(enabled, maxConcurrentConnectionsPerIp, maxNewConnectionsPerSecondPerIp,
        newConnectionsBurstPerIp, maxConcurrentConnectionsGlobal,
        maxNewConnectionsPerSecondGlobal, maxLoginAttemptsPerSecondPerIp,
        loginAttemptsBurstPerIp, maxStatusRequestsPerSecondPerIp, statusRequestsBurstPerIp,
        abuseThreshold, abuseWindowSeconds, abusePenaltySeconds,
        DEFAULT.discordWebhookUrl, DEFAULT.attackNotifyStart, DEFAULT.attackNotifyEnd,
        DEFAULT.attackDetectThreshold, DEFAULT.attackDetectWindowSeconds,
        DEFAULT.attackEndQuietSeconds, DEFAULT.attackReportDir);
  }

  /**
   * Creates a configuration with explicit values, including attack-alert settings.
   *
   * @param enabled master switch for connection-abuse protections
   * @param maxConcurrentConnectionsPerIp simultaneous connections per source ({@code <= 0} disables)
   * @param maxNewConnectionsPerSecondPerIp sustained new connections per source ({@code <= 0} disables)
   * @param newConnectionsBurstPerIp burst allowance for new connections
   * @param maxConcurrentConnectionsGlobal simultaneous connections proxy-wide ({@code <= 0} disables)
   * @param maxNewConnectionsPerSecondGlobal sustained new connections proxy-wide ({@code <= 0} disables)
   * @param maxLoginAttemptsPerSecondPerIp sustained login attempts per source ({@code <= 0} disables)
   * @param loginAttemptsBurstPerIp burst allowance for login attempts
   * @param maxStatusRequestsPerSecondPerIp sustained status requests per source ({@code <= 0} disables)
   * @param statusRequestsBurstPerIp burst allowance for status requests
   * @param abuseThreshold violations within the window that trigger a temporary penalty
   * @param abuseWindowSeconds window in which violations are counted
   * @param abusePenaltySeconds penalty duration ({@code 0} counts without penalizing)
   * @param discordWebhookUrl Discord webhook URL for attack alerts ({@code ""} disables webhooks)
   * @param attackNotifyStart whether to notify when an attack starts
   * @param attackNotifyEnd whether to notify when an attack ends (summary)
   * @param attackDetectThreshold blocked events within the window that declare an attack
   * @param attackDetectWindowSeconds window in which blocked events are counted
   * @param attackEndQuietSeconds quiet period with no flood before the attack is closed
   * @param attackReportDir directory for fallback attack-report files
   */
  public SecurityConfig(final boolean enabled,
      final int maxConcurrentConnectionsPerIp,
      final int maxNewConnectionsPerSecondPerIp,
      final int newConnectionsBurstPerIp,
      final int maxConcurrentConnectionsGlobal,
      final int maxNewConnectionsPerSecondGlobal,
      final int maxLoginAttemptsPerSecondPerIp,
      final int loginAttemptsBurstPerIp,
      final int maxStatusRequestsPerSecondPerIp,
      final int statusRequestsBurstPerIp,
      final int abuseThreshold,
      final int abuseWindowSeconds,
      final int abusePenaltySeconds,
      final String discordWebhookUrl,
      final boolean attackNotifyStart,
      final boolean attackNotifyEnd,
      final int attackDetectThreshold,
      final int attackDetectWindowSeconds,
      final int attackEndQuietSeconds,
      final String attackReportDir) {
    this.enabled = enabled;
    this.maxConcurrentConnectionsPerIp = maxConcurrentConnectionsPerIp;
    this.maxNewConnectionsPerSecondPerIp = maxNewConnectionsPerSecondPerIp;
    this.newConnectionsBurstPerIp = newConnectionsBurstPerIp;
    this.maxConcurrentConnectionsGlobal = maxConcurrentConnectionsGlobal;
    this.maxNewConnectionsPerSecondGlobal = maxNewConnectionsPerSecondGlobal;
    this.maxLoginAttemptsPerSecondPerIp = maxLoginAttemptsPerSecondPerIp;
    this.loginAttemptsBurstPerIp = loginAttemptsBurstPerIp;
    this.maxStatusRequestsPerSecondPerIp = maxStatusRequestsPerSecondPerIp;
    this.statusRequestsBurstPerIp = statusRequestsBurstPerIp;
    this.abuseThreshold = abuseThreshold;
    this.abuseWindowSeconds = abuseWindowSeconds;
    this.abusePenaltySeconds = abusePenaltySeconds;
    this.discordWebhookUrl = discordWebhookUrl == null ? "" : discordWebhookUrl.trim();
    this.attackNotifyStart = attackNotifyStart;
    this.attackNotifyEnd = attackNotifyEnd;
    this.attackDetectThreshold = attackDetectThreshold;
    this.attackDetectWindowSeconds = attackDetectWindowSeconds;
    this.attackEndQuietSeconds = attackEndQuietSeconds;
    this.attackReportDir = attackReportDir == null || attackReportDir.isBlank()
        ? "attack-reports" : attackReportDir.trim();
  }

  /**
   * Loads the configuration from {@code file}, creating it from the bundled defaults when
   * absent. An empty file means {@link #DEFAULT}. Unknown keys and wrong value types fail
   * closed with a clear error instead of silently falling back to defaults.
   *
   * @param file path to {@code secure.yml}
   * @return the parsed configuration (call {@link #validate()} to check the values)
   * @throws IOException if the file cannot be read, parsed, or created
   */
  public static SecurityConfig load(final Path file) throws IOException {
    if (Files.notExists(file)) {
      try (final InputStream defaults =
          SecurityConfig.class.getResourceAsStream(DEFAULT_RESOURCE)) {
        if (defaults == null) {
          throw new IOException("Bundled " + DEFAULT_RESOURCE + " is missing from the jar.");
        }
        Files.copy(defaults, file);
      }
      logger.info("Created default {} - review its connection-abuse protections.", file);
      return DEFAULT;
    }
    final Object loaded;
    try (final InputStream in = Files.newInputStream(file)) {
      // SafeConstructor: only plain maps, lists, strings, and numbers can load. This rules
      // out YAML deserialization gadgets by construction.
      loaded = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
    } catch (final Exception e) {
      throw new IOException("Unable to parse " + file + ": " + e.getMessage(), e);
    }
    if (loaded == null) {
      appendMissingKeys(file, knownKeys());
      return DEFAULT;
    }
    if (!(loaded instanceof Map)) {
      throw new IOException(FILE_NAME + " must contain a key-value mapping.");
    }
    final Map<?, ?> values = (Map<?, ?>) loaded;
    appendMissingKeys(file, missingKeys(values));
    try {
      return fromMap(values);
    } catch (final IllegalArgumentException e) {
      throw new IOException("Invalid " + file + ": " + e.getMessage(), e);
    }
  }

  /**
   * Returns every known configuration key.
   *
   * @return known keys
   */
  static Set<String> knownKeys() {
    return new HashSet<>(List.of(
        "enabled",
        "max-concurrent-connections-per-ip",
        "max-new-connections-per-second-per-ip",
        "new-connections-burst-per-ip",
        "max-concurrent-connections-global",
        "max-new-connections-per-second-global",
        "max-login-attempts-per-second-per-ip",
        "login-attempts-burst-per-ip",
        "max-status-requests-per-second-per-ip",
        "status-requests-burst-per-ip",
        "abuse-penalty-threshold",
        "abuse-window-seconds",
        "abuse-penalty-seconds",
        "discord-webhook-url",
        "attack-notify-start",
        "attack-notify-end",
        "attack-detect-threshold",
        "attack-detect-window-seconds",
        "attack-end-quiet-seconds",
        "attack-report-dir"));
  }

  private static Set<String> missingKeys(final Map<?, ?> values) {
    final Set<String> missing = knownKeys();
    for (final Object key : values.keySet()) {
      missing.remove(String.valueOf(key));
    }
    return missing;
  }

  /**
   * Appends absent keys (with defaults and short comments) to the end of an existing
   * {@code secure.yml}. Existing values and comments are never touched; only keys
   * introduced by newer versions are added. Failures are logged, never fatal.
   *
   * @param file the configuration file
   * @param missing keys absent from the file
   */
  private static void appendMissingKeys(final Path file, final Set<String> missing) {
    if (missing.isEmpty()) {
      return;
    }
    try {
      String existing = Files.readString(file);
      final StringBuilder block = new StringBuilder();
      if (!existing.isEmpty() && !existing.endsWith("\n")) {
        block.append('\n');
      }
      block.append("\n# Added automatically: new options from a newer version, "
          + "with default values.\n");
      block.append("# Your existing settings above were left untouched.\n");
      for (final String key : List.of(
          "discord-webhook-url",
          "attack-notify-start",
          "attack-notify-end",
          "attack-detect-threshold",
          "attack-detect-window-seconds",
          "attack-end-quiet-seconds",
          "attack-report-dir")) {
        if (missing.contains(key)) {
          block.append(defaultComment(key));
          block.append(key).append(": ").append(defaultYaml(key)).append('\n');
        }
      }
      // Any other missing key (older option absent for any reason) is appended
      // without a comment rather than skipped.
      for (final String key : missing) {
        if (!isDocumentedNewKey(key)) {
          block.append(key).append(": ").append(defaultYaml(key)).append('\n');
        }
      }
      Files.writeString(file, block.toString(),
          java.nio.file.StandardOpenOption.APPEND);
      logger.info("Added {} missing option(s) with defaults to {}: {}.",
          missing.size(), file, String.join(", ", missing));
    } catch (final Exception e) {
      // The in-memory defaults still apply; the file just keeps its old shape.
      logger.warn("Could not append missing options to {}, continuing with defaults.", file, e);
    }
  }

  private static boolean isDocumentedNewKey(final String key) {
    return switch (key) {
      case "discord-webhook-url", "attack-notify-start", "attack-notify-end",
          "attack-detect-threshold", "attack-detect-window-seconds", "attack-end-quiet-seconds",
          "attack-report-dir" -> true;
      default -> false;
    };
  }

  private static String defaultComment(final String key) {
    return switch (key) {
      case "discord-webhook-url" -> "# Discord webhook for attack alerts (empty = disabled, "
          + "file fallback still works).\n";
      case "attack-notify-start" -> "# Alert when an attack starts.\n";
      case "attack-notify-end" -> "# Send a summary when an attack ends.\n";
      case "attack-detect-threshold" -> "# Blocked events within the window that declare an attack.\n";
      case "attack-detect-window-seconds" -> "# Window in which blocked events are counted.\n";
      case "attack-end-quiet-seconds" -> "# Quiet period before an attack is considered over.\n";
      case "attack-report-dir" -> "# Directory for fallback attack-report files.\n";
      default -> "";
    };
  }

  private static String defaultYaml(final String key) {
    final SecurityConfig defaults = DEFAULT;
    return switch (key) {
      case "enabled" -> Boolean.toString(defaults.enabled);
      case "max-concurrent-connections-per-ip" ->
          Integer.toString(defaults.maxConcurrentConnectionsPerIp);
      case "max-new-connections-per-second-per-ip" ->
          Integer.toString(defaults.maxNewConnectionsPerSecondPerIp);
      case "new-connections-burst-per-ip" ->
          Integer.toString(defaults.newConnectionsBurstPerIp);
      case "max-concurrent-connections-global" ->
          Integer.toString(defaults.maxConcurrentConnectionsGlobal);
      case "max-new-connections-per-second-global" ->
          Integer.toString(defaults.maxNewConnectionsPerSecondGlobal);
      case "max-login-attempts-per-second-per-ip" ->
          Integer.toString(defaults.maxLoginAttemptsPerSecondPerIp);
      case "login-attempts-burst-per-ip" ->
          Integer.toString(defaults.loginAttemptsBurstPerIp);
      case "max-status-requests-per-second-per-ip" ->
          Integer.toString(defaults.maxStatusRequestsPerSecondPerIp);
      case "status-requests-burst-per-ip" ->
          Integer.toString(defaults.statusRequestsBurstPerIp);
      case "abuse-penalty-threshold" -> Integer.toString(defaults.abuseThreshold);
      case "abuse-window-seconds" -> Integer.toString(defaults.abuseWindowSeconds);
      case "abuse-penalty-seconds" -> Integer.toString(defaults.abusePenaltySeconds);
      case "discord-webhook-url" -> "\"" + defaults.discordWebhookUrl + "\"";
      case "attack-notify-start" -> Boolean.toString(defaults.attackNotifyStart);
      case "attack-notify-end" -> Boolean.toString(defaults.attackNotifyEnd);
      case "attack-detect-threshold" -> Integer.toString(defaults.attackDetectThreshold);
      case "attack-detect-window-seconds" ->
          Integer.toString(defaults.attackDetectWindowSeconds);
      case "attack-end-quiet-seconds" -> Integer.toString(defaults.attackEndQuietSeconds);
      case "attack-report-dir" -> "\"" + defaults.attackReportDir + "\"";
      default -> throw new IllegalArgumentException("unknown key '" + key + "'");
    };
  }

  /**
   * Builds a configuration from already-parsed values, falling back to defaults per key.
   *
   * @param values the parsed mapping
   * @return the configuration
   * @throws IllegalArgumentException on unknown keys or mistyped values
   */
  public static SecurityConfig fromMap(final Map<?, ?> values) {
    final Set<String> known = knownKeys();
    for (final Object key : values.keySet()) {
      if (!known.contains(String.valueOf(key))) {
        throw new IllegalArgumentException("unknown key '" + key + "'");
      }
    }
    return new SecurityConfig(
        getBool(values, "enabled", DEFAULT.enabled),
        getInt(values, "max-concurrent-connections-per-ip",
            DEFAULT.maxConcurrentConnectionsPerIp),
        getInt(values, "max-new-connections-per-second-per-ip",
            DEFAULT.maxNewConnectionsPerSecondPerIp),
        getInt(values, "new-connections-burst-per-ip", DEFAULT.newConnectionsBurstPerIp),
        getInt(values, "max-concurrent-connections-global",
            DEFAULT.maxConcurrentConnectionsGlobal),
        getInt(values, "max-new-connections-per-second-global",
            DEFAULT.maxNewConnectionsPerSecondGlobal),
        getInt(values, "max-login-attempts-per-second-per-ip",
            DEFAULT.maxLoginAttemptsPerSecondPerIp),
        getInt(values, "login-attempts-burst-per-ip", DEFAULT.loginAttemptsBurstPerIp),
        getInt(values, "max-status-requests-per-second-per-ip",
            DEFAULT.maxStatusRequestsPerSecondPerIp),
        getInt(values, "status-requests-burst-per-ip", DEFAULT.statusRequestsBurstPerIp),
        getInt(values, "abuse-penalty-threshold", DEFAULT.abuseThreshold),
        getInt(values, "abuse-window-seconds", DEFAULT.abuseWindowSeconds),
        getInt(values, "abuse-penalty-seconds", DEFAULT.abusePenaltySeconds),
        getString(values, "discord-webhook-url", DEFAULT.discordWebhookUrl),
        getBool(values, "attack-notify-start", DEFAULT.attackNotifyStart),
        getBool(values, "attack-notify-end", DEFAULT.attackNotifyEnd),
        getInt(values, "attack-detect-threshold", DEFAULT.attackDetectThreshold),
        getInt(values, "attack-detect-window-seconds", DEFAULT.attackDetectWindowSeconds),
        getInt(values, "attack-end-quiet-seconds", DEFAULT.attackEndQuietSeconds),
        getString(values, "attack-report-dir", DEFAULT.attackReportDir));
  }

  private static boolean getBool(final Map<?, ?> values, final String key,
      final boolean def) {
    final Object value = values.get(key);
    if (value == null) {
      return def;
    }
    if (value instanceof Boolean) {
      return (Boolean) value;
    }
    throw new IllegalArgumentException("key '" + key + "' must be true or false");
  }

  private static int getInt(final Map<?, ?> values, final String key, final int def) {
    final Object value = values.get(key);
    if (value == null) {
      return def;
    }
    if (value instanceof Number) {
      final double asDouble = ((Number) value).doubleValue();
      if (asDouble != Math.rint(asDouble)) {
        throw new IllegalArgumentException("key '" + key + "' must be a whole number");
      }
      final long asLong = (long) asDouble;
      if (asLong < Integer.MIN_VALUE || asLong > Integer.MAX_VALUE) {
        throw new IllegalArgumentException("key '" + key + "' is out of range");
      }
      return (int) asLong;
    }
    throw new IllegalArgumentException("key '" + key + "' must be a number");
  }

  private static String getString(final Map<?, ?> values, final String key,
      final String def) {
    final Object value = values.get(key);
    if (value == null) {
      return def;
    }
    if (value instanceof String) {
      return ((String) value).trim();
    }
    throw new IllegalArgumentException("key '" + key + "' must be a string");
  }

  /**
   * Validates the values, collecting human-readable errors for anything nonsensical.
   *
   * @return list of errors; empty means the configuration is usable
   */
  public List<String> validate() {
    final List<String> errors = new ArrayList<>();
    if (maxNewConnectionsPerSecondPerIp < 0) {
      errors.add("'max-new-connections-per-second-per-ip' must not be negative (0 disables).");
    }
    if (maxNewConnectionsPerSecondGlobal < 0) {
      errors.add("'max-new-connections-per-second-global' must not be negative (0 disables).");
    }
    if (maxLoginAttemptsPerSecondPerIp < 0) {
      errors.add("'max-login-attempts-per-second-per-ip' must not be negative (0 disables).");
    }
    if (maxStatusRequestsPerSecondPerIp < 0) {
      errors.add("'max-status-requests-per-second-per-ip' must not be negative (0 disables).");
    }
    if (maxConcurrentConnectionsPerIp < 0) {
      errors.add("'max-concurrent-connections-per-ip' must not be negative (0 disables).");
    }
    if (maxConcurrentConnectionsGlobal < 0) {
      errors.add("'max-concurrent-connections-global' must not be negative (0 disables).");
    }
    if (newConnectionsBurstPerIp < 1) {
      errors.add("'new-connections-burst-per-ip' must be at least 1.");
    }
    if (loginAttemptsBurstPerIp < 1) {
      errors.add("'login-attempts-burst-per-ip' must be at least 1.");
    }
    if (statusRequestsBurstPerIp < 1) {
      errors.add("'status-requests-burst-per-ip' must be at least 1.");
    }
    if (abuseThreshold < 1) {
      errors.add("'abuse-penalty-threshold' must be at least 1.");
    }
    if (abuseWindowSeconds < 1) {
      errors.add("'abuse-window-seconds' must be at least 1.");
    }
    if (abusePenaltySeconds < 0) {
      errors.add("'abuse-penalty-seconds' must not be negative (0 counts without penalizing).");
    }
    if (!discordWebhookUrl.isEmpty() && !discordWebhookUrl.startsWith("https://")) {
      errors.add("'discord-webhook-url' must be empty (disabled) or start with 'https://'.");
    }
    if (attackDetectThreshold < 1) {
      errors.add("'attack-detect-threshold' must be at least 1.");
    }
    if (attackDetectWindowSeconds < 5) {
      errors.add("'attack-detect-window-seconds' must be at least 5.");
    }
    if (attackEndQuietSeconds < 10) {
      errors.add("'attack-end-quiet-seconds' must be at least 10.");
    }
    if (attackReportDir.isBlank()) {
      errors.add("'attack-report-dir' must not be blank.");
    }
    return errors;
  }

  /**
   * Returns whether connection-abuse protections are enabled.
   *
   * @return {@code true} if enabled
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * Returns the maximum simultaneous connections per source ({@code <= 0} disables).
   *
   * @return the limit
   */
  public int getMaxConcurrentConnectionsPerIp() {
    return maxConcurrentConnectionsPerIp;
  }

  /**
   * Returns the sustained new-connection rate per source ({@code <= 0} disables).
   *
   * @return connections per second
   */
  public int getMaxNewConnectionsPerSecondPerIp() {
    return maxNewConnectionsPerSecondPerIp;
  }

  /**
   * Returns the burst allowance for new connections per source.
   *
   * @return burst size
   */
  public int getNewConnectionsBurstPerIp() {
    return newConnectionsBurstPerIp;
  }

  /**
   * Returns the maximum simultaneous connections proxy-wide ({@code <= 0} disables).
   *
   * @return the limit
   */
  public int getMaxConcurrentConnectionsGlobal() {
    return maxConcurrentConnectionsGlobal;
  }

  /**
   * Returns the sustained new-connection rate proxy-wide ({@code <= 0} disables).
   *
   * @return connections per second
   */
  public int getMaxNewConnectionsPerSecondGlobal() {
    return maxNewConnectionsPerSecondGlobal;
  }

  /**
   * Returns the sustained login-attempt rate per source ({@code <= 0} disables).
   *
   * @return logins per second
   */
  public int getMaxLoginAttemptsPerSecondPerIp() {
    return maxLoginAttemptsPerSecondPerIp;
  }

  /**
   * Returns the burst allowance for login attempts per source.
   *
   * @return burst size
   */
  public int getLoginAttemptsBurstPerIp() {
    return loginAttemptsBurstPerIp;
  }

  /**
   * Returns the sustained status-request rate per source ({@code <= 0} disables).
   *
   * @return requests per second
   */
  public int getMaxStatusRequestsPerSecondPerIp() {
    return maxStatusRequestsPerSecondPerIp;
  }

  /**
   * Returns the burst allowance for status requests per source.
   *
   * @return burst size
   */
  public int getStatusRequestsBurstPerIp() {
    return statusRequestsBurstPerIp;
  }

  /**
   * Returns how many violations within the window trigger a temporary penalty.
   *
   * @return the threshold
   */
  public int getAbuseThreshold() {
    return abuseThreshold;
  }

  /**
   * Returns the window in seconds in which violations are counted.
   *
   * @return window seconds
   */
  public int getAbuseWindowSeconds() {
    return abuseWindowSeconds;
  }

  /**
   * Returns the penalty duration in seconds ({@code 0} counts without penalizing).
   *
   * @return penalty seconds
   */
  public int getAbusePenaltySeconds() {
    return abusePenaltySeconds;
  }

  /**
   * Returns the Discord webhook URL for attack alerts ({@code ""} disables webhooks).
   * The URL itself is never logged.
   *
   * @return the webhook URL or empty string
   */
  public String getDiscordWebhookUrl() {
    return discordWebhookUrl;
  }

  /**
   * Returns whether an alert is sent when an attack starts.
   *
   * @return {@code true} if start alerts are enabled
   */
  public boolean isAttackNotifyStart() {
    return attackNotifyStart;
  }

  /**
   * Returns whether a summary is sent when an attack ends.
   *
   * @return {@code true} if end summaries are enabled
   */
  public boolean isAttackNotifyEnd() {
    return attackNotifyEnd;
  }

  /**
   * Returns how many blocked events within the window declare an attack.
   *
   * @return the detection threshold
   */
  public int getAttackDetectThreshold() {
    return attackDetectThreshold;
  }

  /**
   * Returns the window in seconds in which blocked events are counted.
   *
   * @return window seconds
   */
  public int getAttackDetectWindowSeconds() {
    return attackDetectWindowSeconds;
  }

  /**
   * Returns the quiet period in seconds before an attack is considered over.
   *
   * @return quiet seconds
   */
  public int getAttackEndQuietSeconds() {
    return attackEndQuietSeconds;
  }

  /**
   * Returns the directory for fallback attack-report files.
   *
   * @return the report directory
   */
  public String getAttackReportDir() {
    return attackReportDir;
  }

  @Override
  public String toString() {
    return "SecurityConfig{"
        + "enabled=" + enabled
        + ", maxConcurrentConnectionsPerIp=" + maxConcurrentConnectionsPerIp
        + ", maxNewConnectionsPerSecondPerIp=" + maxNewConnectionsPerSecondPerIp
        + ", newConnectionsBurstPerIp=" + newConnectionsBurstPerIp
        + ", maxConcurrentConnectionsGlobal=" + maxConcurrentConnectionsGlobal
        + ", maxNewConnectionsPerSecondGlobal=" + maxNewConnectionsPerSecondGlobal
        + ", maxLoginAttemptsPerSecondPerIp=" + maxLoginAttemptsPerSecondPerIp
        + ", loginAttemptsBurstPerIp=" + loginAttemptsBurstPerIp
        + ", maxStatusRequestsPerSecondPerIp=" + maxStatusRequestsPerSecondPerIp
        + ", statusRequestsBurstPerIp=" + statusRequestsBurstPerIp
        + ", abuseThreshold=" + abuseThreshold
        + ", abuseWindowSeconds=" + abuseWindowSeconds
        + ", abusePenaltySeconds=" + abusePenaltySeconds
        + ", discordWebhookConfigured=" + (!discordWebhookUrl.isEmpty())
        + ", attackNotifyStart=" + attackNotifyStart
        + ", attackNotifyEnd=" + attackNotifyEnd
        + ", attackDetectThreshold=" + attackDetectThreshold
        + ", attackDetectWindowSeconds=" + attackDetectWindowSeconds
        + ", attackEndQuietSeconds=" + attackEndQuietSeconds
        + ", attackReportDir='" + attackReportDir + '\''
        + '}';
  }
}
