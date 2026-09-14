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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Minimal Discord webhook client with no extra dependencies.
 *
 * <p>Sends pre-built JSON payloads off the calling thread. The webhook URL is never
 * logged. Any failure is reported as an exception so callers can fall back to a
 * local report file.</p>
 */
public final class DiscordWebhookSender {

  private static final Logger logger = LogManager.getLogger(DiscordWebhookSender.class);
  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private final HttpClient http;
  private volatile String webhookUrl;

  /**
   * Creates a sender.
   *
   * @param webhookUrl initial webhook URL (empty disables delivery)
   */
  public DiscordWebhookSender(final String webhookUrl) {
    this.http = HttpClient.newBuilder()
        .connectTimeout(TIMEOUT)
        .build();
    this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
  }

  /**
   * Updates the webhook URL (used on {@code /velocity reload}).
   *
   * @param webhookUrl new URL, empty disables delivery
   */
  public void setWebhookUrl(final String webhookUrl) {
    this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
  }

  /**
   * Returns whether delivery is configured.
   *
   * @return {@code true} when a non-empty URL is set
   */
  public boolean isConfigured() {
    return !webhookUrl.isEmpty();
  }

  /**
   * Sends a Discord payload asynchronously.
   *
   * @param json already-escaped Discord JSON payload
   * @return future resolving to {@code true} on HTTP 2xx
   */
  public CompletableFuture<Boolean> send(final String json) {
    final String url = this.webhookUrl;
    if (url.isEmpty()) {
      return CompletableFuture.completedFuture(false);
    }
    final HttpRequest request;
    try {
      request = HttpRequest.newBuilder()
          .uri(URI.create(url))
          .timeout(TIMEOUT)
          .header("Content-Type", "application/json")
          .header("User-Agent", "Velocity-AntiBot/1.0")
          .POST(HttpRequest.BodyPublishers.ofString(json))
          .build();
    } catch (final IllegalArgumentException e) {
      logger.warn("Invalid Discord webhook URL, skipping delivery.");
      final CompletableFuture<Boolean> failed = new CompletableFuture<>();
      failed.completeExceptionally(new IOException("Invalid webhook URL", e));
      return failed;
    }
    return http.sendAsync(request, HttpResponse.BodyHandlers.discarding())
        .thenApply(response -> {
          final int status = response.statusCode();
          if (status >= 200 && status < 300) {
            return true;
          }
          throw new RuntimeException("Discord webhook returned HTTP " + status);
        });
  }

  /**
   * Escapes a string for embedding in JSON.
   *
   * @param value raw text
   * @return JSON-escaped text (without surrounding quotes)
   */
  public static String escape(final String value) {
    if (value == null) {
      return "";
    }
    final StringBuilder out = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      final char c = value.charAt(i);
      switch (c) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
          break;
      }
    }
    return out.toString();
  }
}
