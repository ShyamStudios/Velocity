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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

class SecurityConfigTest {

  @Test
  void defaultsAreValid() {
    assertTrue(SecurityConfig.DEFAULT.validate().isEmpty());
    assertTrue(SecurityConfig.DEFAULT.isEnabled());
  }

  @Test
  void missingKeysFallBackToDefaults() {
    final SecurityConfig config = SecurityConfig.fromMap(Map.of());
    assertEquals(SecurityConfig.DEFAULT.getMaxConcurrentConnectionsPerIp(),
        config.getMaxConcurrentConnectionsPerIp());
    assertEquals(SecurityConfig.DEFAULT.getAbusePenaltySeconds(),
        config.getAbusePenaltySeconds());
    assertTrue(config.validate().isEmpty());
  }

  @Test
  void customValuesAreHonored() {
    final Map<String, Object> values = new HashMap<>();
    values.put("enabled", false);
    values.put("max-concurrent-connections-per-ip", 7);
    values.put("abuse-penalty-seconds", 0);
    final SecurityConfig config = SecurityConfig.fromMap(values);
    assertFalse(config.isEnabled());
    assertEquals(7, config.getMaxConcurrentConnectionsPerIp());
    assertEquals(0, config.getAbusePenaltySeconds());
    assertTrue(config.validate().isEmpty());
  }

  @Test
  void unknownKeysFailClosed() {
    assertThrows(IllegalArgumentException.class,
        () -> SecurityConfig.fromMap(Map.of("max-concurrent-per-ip", 5)));
  }

  @Test
  void mistypedValuesFailClosed() {
    assertThrows(IllegalArgumentException.class,
        () -> SecurityConfig.fromMap(Map.of("enabled", "yes please")));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityConfig.fromMap(Map.of("max-concurrent-connections-per-ip", "many")));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityConfig.fromMap(Map.of("max-concurrent-connections-per-ip", 2.5)));
  }

  @Test
  void nonsenseValuesAreReported() {
    final Map<String, Object> values = new HashMap<>();
    values.put("max-new-connections-per-second-per-ip", -3);
    values.put("new-connections-burst-per-ip", 0);
    values.put("abuse-penalty-threshold", 0);
    values.put("abuse-window-seconds", 0);
    values.put("abuse-penalty-seconds", -1);
    assertEquals(5, SecurityConfig.fromMap(values).validate().size());
  }

  @Test
  void zeroDisablesIndividualChecks() {
    final Map<String, Object> values = new HashMap<>();
    values.put("max-new-connections-per-second-per-ip", 0);
    values.put("max-concurrent-connections-per-ip", 0);
    values.put("max-concurrent-connections-global", 0);
    assertTrue(SecurityConfig.fromMap(values).validate().isEmpty());
  }

  @Test
  void loadCreatesDefaultsWhenAbsent(@TempDir final Path dir) throws IOException {
    final Path file = dir.resolve("secure.yml");
    final SecurityConfig config = SecurityConfig.load(file);
    assertTrue(Files.exists(file), "first boot must materialize a documented file");
    assertEquals(SecurityConfig.DEFAULT.getMaxStatusRequestsPerSecondPerIp(),
        config.getMaxStatusRequestsPerSecondPerIp());
  }

  @Test
  void loadReadsCustomFile(@TempDir final Path dir) throws IOException {
    final Path file = dir.resolve("secure.yml");
    Files.writeString(file, "max-concurrent-connections-per-ip: 9\nenabled: false\n");
    final SecurityConfig config = SecurityConfig.load(file);
    assertEquals(9, config.getMaxConcurrentConnectionsPerIp());
    assertFalse(config.isEnabled());
  }

  @Test
  void loadRejectsGarbage(@TempDir final Path dir) throws IOException {
    final Path file = dir.resolve("secure.yml");
    Files.writeString(file, "max-concurrent-connections-per-ip: [unclosed\n");
    assertThrows(IOException.class, () -> SecurityConfig.load(file));
  }

  @Test
  void loadRejectsUnknownKeys(@TempDir final Path dir) throws IOException {
    final Path file = dir.resolve("secure.yml");
    Files.writeString(file, "max-concurrent-per-ip: 5\n");
    assertThrows(IOException.class, () -> SecurityConfig.load(file));
  }

  @Test
  void bundledDefaultsAreValid() throws Exception {
    // The file written on first boot must itself parse and validate.
    final Yaml yaml =
        new Yaml(new SafeConstructor(new LoaderOptions()));
    final Object loaded;
    try (final InputStream in =
        SecurityConfig.class.getResourceAsStream("/default-secure.yml")) {
      assertTrue(in != null, "default-secure.yml must be packaged");
      loaded = yaml.load(in);
    }
    final SecurityConfig config = SecurityConfig.fromMap((Map<?, ?>) loaded);
    assertTrue(config.validate().isEmpty());
    assertEquals(SecurityConfig.DEFAULT.getMaxConcurrentConnectionsPerIp(),
        config.getMaxConcurrentConnectionsPerIp());
  }
}
