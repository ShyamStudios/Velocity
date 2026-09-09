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
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class IpKeyTest {

  @Test
  void ipv4Equality() throws UnknownHostException {
    assertEquals(IpKey.of(InetAddress.getByName("1.2.3.4")),
        IpKey.of(InetAddress.getByName("1.2.3.4")));
    assertNotEquals(IpKey.of(InetAddress.getByName("1.2.3.4")),
        IpKey.of(InetAddress.getByName("1.2.3.5")));
  }

  @Test
  void ipv6GroupedBySlash64() throws UnknownHostException {
    assertEquals(IpKey.of(InetAddress.getByName("2001:db8::1")),
        IpKey.of(InetAddress.getByName("2001:db8::ffff")),
        "same /64 must share a key so low-bit rotation does not evade limits");
    assertNotEquals(IpKey.of(InetAddress.getByName("2001:db8::1")),
        IpKey.of(InetAddress.getByName("2001:db8:0:1::1")),
        "different /64 must not share a key");
  }

  @Test
  void familiesNeverCollide() throws UnknownHostException {
    // Note: ::ffff:127.0.0.1 is normalized to IPv4 by java.net itself, so it must (correctly)
    // share the IPv4 key. A genuine IPv6 address must not.
    assertEquals(IpKey.of(InetAddress.getByName("127.0.0.1")),
        IpKey.of(InetAddress.getByName("::ffff:127.0.0.1")));
    assertNotEquals(IpKey.of(InetAddress.getByName("127.0.0.1")),
        IpKey.of(InetAddress.getByName("::1")));
  }
}
