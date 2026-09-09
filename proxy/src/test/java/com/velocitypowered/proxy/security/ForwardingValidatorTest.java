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

import org.junit.jupiter.api.Test;

class ForwardingValidatorTest {

  @Test
  void cleanHostsPassThroughIdentical() {
    assertEquals("play.example.com", ForwardingValidator.sanitizeVhost("play.example.com"));
    assertEquals("", ForwardingValidator.sanitizeVhost(""));
  }

  @Test
  void nullBecomesEmpty() {
    assertEquals("", ForwardingValidator.sanitizeVhost(null));
  }

  @Test
  void separatorSmugglingIsCut() {
    assertEquals("play.example.com",
        ForwardingValidator.sanitizeVhost("play.example.com\0attacker\0data"));
    assertEquals("", ForwardingValidator.sanitizeVhost("\0attacker"));
  }
}
