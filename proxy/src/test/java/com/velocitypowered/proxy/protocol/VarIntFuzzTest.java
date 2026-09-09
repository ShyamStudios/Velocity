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

package com.velocitypowered.proxy.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DecoderException;
import java.time.Duration;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Feeds hostile and random bytes into VarInt decoding. Every input must either decode to the
 * exact value a reference decoder produces or fail with a {@link DecoderException}: never hang,
 * never corrupt the buffer, never throw anything else.
 */
class VarIntFuzzTest {

  private static int referenceDecode(final byte[] bytes) {
    int value = 0;
    int shift = 0;
    for (final byte raw : bytes) {
      final int current = raw & 0xFF;
      value |= (current & 0x7F) << shift;
      if ((current & 0x80) == 0) {
        return value;
      }
      shift += 7;
      if (shift >= 35) {
        throw new DecoderException("too big");
      }
    }
    throw new DecoderException("truncated");
  }

  private static void assertDecodesLikeReference(final byte[] input) {
    final ByteBuf buf = Unpooled.wrappedBuffer(input);
    try {
      int ours = 0;
      boolean threw = false;
      try {
        ours = ProtocolUtils.readVarInt(buf);
      } catch (final DecoderException expected) {
        threw = true;
      }
      assertTrue(buf.readerIndex() >= 0 && buf.readerIndex() <= input.length,
          "reader index must stay sane");
      if (threw) {
        return;
      }
      assertEquals(referenceDecode(input), ours, "decoders must agree");
    } catch (final AssertionError e) {
      throw e;
    } catch (final Throwable t) {
      fail("unexpected " + t + " for input length " + input.length);
    } finally {
      buf.release();
    }
  }

  @Test
  void hostileInputs() {
    final byte[][] cases = {
        {},
        {(byte) 0x80},
        {(byte) 0x80, (byte) 0x80},
        {(byte) 0x80, (byte) 0x80, (byte) 0x80},
        {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80},
        {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80},
        {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
        {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x07},
        {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x08},
        {0x00}, {0x01}, {0x7F}, {(byte) 0xAC, 0x02},
    };
    for (final byte[] input : cases) {
      assertDecodesLikeReference(input);
    }
  }

  @Test
  void randomInputsAlwaysTerminateCleanly() {
    assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
      final Random random = new Random(0x5EC017L);
      for (int iter = 0; iter < 50_000; iter++) {
        final int length = random.nextInt(8);
        final byte[] input = new byte[length];
        random.nextBytes(input);
        // Bias toward continuation-heavy hostile shapes.
        if (iter % 3 == 0) {
          for (int i = 0; i < length; i++) {
            input[i] |= (byte) 0x80;
          }
        }
        assertDecodesLikeReference(input);
      }
    });
  }
}
