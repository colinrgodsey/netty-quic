package com.colingodsey.quic.utils;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class VariableIntTest {
    final List<Tuple<Long, ByteBuf>> values = new ArrayList<>();
    final ByteBuf b = Unpooled.buffer();

    {
        values.add(Tuple.create(151288809941952652L,  b.copy().writeLong( 0xc2197c5eff14e88cL)));
        values.add(Tuple.create(494878333L,           b.copy().writeInt(          0x9d7f3e7d)));
        values.add(Tuple.create(15293L,               b.copy().writeShort(            0x7bbd)));
        values.add(Tuple.create(37L,                  b.copy().writeByte(               0x25)));
    }

    @Test
    public void decode() {
        values.forEach(pair -> assertEquals((long) pair.getA(),
                VariableInt.read(pair.getB().duplicate())));
        assertEquals(37L, VariableInt.read(b.copy().writeShort(0x4025)));
    }

    @Test
    public void encode() {
        values.forEach(pair -> {
            assertEquals(makeList(pair.getB()), makeList(VariableInt.write(pair.getA(), b.copy())));
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
