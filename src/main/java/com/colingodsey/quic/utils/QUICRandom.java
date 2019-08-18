package com.colingodsey.quic.utils;

import java.util.Random;

//TODO: thread local random
public class QUICRandom {
    private static final Random r = new Random();

    public static int nextInt() {
        return r.nextInt();
    }

    public static byte nextNibble() {
        return (byte) (nextInt() & 0xF);
    }
}
