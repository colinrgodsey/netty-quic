package com.colingodsey.quic.packet.frames;

import it.unimi.dsi.fastutil.longs.LongComparators;
import it.unimi.dsi.fastutil.longs.LongRBTreeSet;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

public class AckTest {
    @Test
    public void firstAck1() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 4L));
        final Ack ack = new Ack(0, set, 0);

        assertEquals(0, ack.ackRangeCount);
        assertEquals(4, ack.firstAck);
    }

    @Test
    public void firstAck2() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(2L, 3L, 4L));
        final Ack ack = new Ack(1, set, 0);

        assertEquals(0, ack.ackRangeCount);
        assertEquals(3, ack.firstAck);
    }

    @Test
    public void tailGap() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(2L, 3L, 4L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(1, ack.ackRangeCount);
        assertEquals(3, ack.firstAck);
    }

    @Test
    public void middleGap() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 10L, 11L, 12L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(1, ack.ackRangeCount);
        assertEquals(3, ack.firstAck);
    }

    @Test
    public void dualMiddleGap() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 10L, 11L, 12L, 14L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(2, ack.ackRangeCount);
        assertEquals(1, ack.firstAck);
    }

    @Test
    public void dualMiddleGap2() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 10L, 11L, 12L, 19L, 20L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(2, ack.ackRangeCount);
        assertEquals(2, ack.firstAck);
    }

    @Test
    public void trippleMiddleGap() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 10L, 11L, 12L, 14L, 15L, 20L, 21L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(3, ack.ackRangeCount);
        assertEquals(2, ack.firstAck);
    }

    @Test(expected = AssertionError.class)
    public void badOrder() {
        final LongRBTreeSet set = new LongRBTreeSet(LongComparators.NATURAL_COMPARATOR);
        set.addAll(Arrays.asList(1L, 2L, 3L, 10L, 11L, 12L, 14L, 15L, 20L, 21L));
        final Ack ack = new Ack(0, set, 0);
        assertEquals(3, ack.ackRangeCount);
        assertEquals(2, ack.firstAck);
    }

    @Test
    public void randomTestEqual() {
        final Random r = new Random(7449);

        for (int i = 0 ; i < 5000 ; i++) {
            final LongRBTreeSet ack = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
            final LongRBTreeSet gap = new LongRBTreeSet();
            for (int n = 1 ; n < 5000 ; n++) {
                if (r.nextDouble() > 0.5 || n == 4999) { //always add last
                    ack.add(n);
                } else {
                    gap.add(n);
                }
            }
            final Ack res = new Ack(0, ack, 0);
            res.forEach(n -> ack.remove(n), n -> gap.remove(n));
            assertTrue(ack.isEmpty());
            assertTrue(gap.isEmpty());
        }
    }

    @Test
    public void randomTestSparse() {
        final Random r = new Random(7448);

        for (int i = 0 ; i < 5000 ; i++) {
            final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
            for (int n = 1 ; n < 5000 ; n++) {
                if (r.nextDouble() > 0.8) {
                    set.add(n);
                }
            }
            final Ack res = new Ack(0, set, 0);
            res.forEach(n -> set.remove(n), n -> {});
            assertTrue(set.isEmpty());
        }
    }

    @Test
    public void randomTestDense() {
        final Random r = new Random(7447);

        for (int i = 0 ; i < 5000 ; i++) {
            final LongRBTreeSet set = new LongRBTreeSet(LongComparators.OPPOSITE_COMPARATOR);
            for (int n = 1 ; n < 5000 ; n++) {
                if (r.nextDouble() > 0.2) {
                    set.add(n);
                }
            }
            final Ack res = new Ack(0, set, 0);
            res.forEach(n -> set.remove(n), n -> {});
            assertTrue(set.isEmpty());
        }
    }
}
