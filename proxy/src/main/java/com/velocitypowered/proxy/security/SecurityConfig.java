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
      true, 32, 10, 20, 50000, 0, 2, 4, 5, 10, 10, 60, 30);

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
      return DEFAULT;
    }
    if (!(loaded instanceof Map)) {
      throw new IOException(FILE_NAME + " must contain a key-value mapping.");
    }
    try {
      return fromMap((Map<?, ?>) loaded);
    } catch (final IllegalArgumentException e) {
      throw new IOException("Invalid " + file + ": " + e.getMessage(), e);
    }
  }

  /**
   * Builds a configuration from already-parsed values, falling back to defaults per key.
   *
   * @param values the parsed mapping
   * @return the configuration
   * @throws IllegalArgumentException on unknown keys or mistyped values
   */
  public static SecurityConfig fromMap(final Map<?, ?> values) {
    final Set<String> known = new HashSet<>(List.of(
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
        "abuse-penalty-seconds"));
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
        getInt(values, "abuse-penalty-seconds", DEFAULT.abusePenaltySeconds));
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
        + '}';
  }
}
