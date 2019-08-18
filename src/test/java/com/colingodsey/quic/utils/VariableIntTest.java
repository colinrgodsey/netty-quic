package com.colingodsey.quic.utils;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;

public class VariableIntTest {
    final List<Entry<Long, ByteBuf>> values = new ArrayList<>();
    final ByteBuf b = Unpooled.buffer();

    {
        values.add(new HashMap.SimpleImmutableEntry<>(151288809941952652L,  b.copy().writeLong( 0xc2197c5eff14e88cL)));
        values.add(new HashMap.SimpleImmutableEntry<>(494878333L,           b.copy().writeInt(          0x9d7f3e7d)));
        values.add(new HashMap.SimpleImmutableEntry<>(15293L,               b.copy().writeShort(            0x7bbd)));
        values.add(new HashMap.SimpleImmutableEntry<>(37L,                  b.copy().writeByte(               0x25)));
    }

    @Test
    public void decode() {
        values.forEach(pair -> assertEquals((long) pair.getKey(),
                VariableInt.read(pair.getValue().duplicate())));
        assertEquals(37L, VariableInt.read(b.copy().writeShort(0x4025)));
    }

    @Test
    public void encode() {
        values.forEach(pair -> {
            assertEquals(makeList(pair.getValue()), makeList(VariableInt.write(pair.getKey(), b.copy())));
        });
    }

    @Test
    public void random() {
        final Random r = new Random(0x84457);

        for(int i = 0 ; i < 4000 ; i++) {
            final long l = r.nextLong() >>> 2;
            assertEquals(l, VariableInt.read(VariableInt.write(l, b.copy())));
        }

        for(int i = 0 ; i < 4000 ; i++) {
            final long l = Math.abs(r.nextInt());
            assertEquals(l, VariableInt.read(VariableInt.write(l, b.copy())));
        }

        for(int i = 0 ; i < 4000 ; i++) {
            final long l = Math.abs(r.nextInt()) & 0xFF;
            assertEquals(l, VariableInt.read(VariableInt.write(l, b.copy())));
        }
    }

    public ArrayList<Byte> makeList(ByteBuf from) {
        from = from.duplicate();
        final ArrayList<Byte> out = new ArrayList<>();
        while (from.isReadable()) out.add(from.readByte());
        return out;
    }
}
