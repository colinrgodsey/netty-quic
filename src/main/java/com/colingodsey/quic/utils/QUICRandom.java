package com.colingodsey.quic.utils;

import java.security.SecureRandom;
import java.util.Random;

public class QUICRandom {
    private static final Random r = new Random();
    private static final SecureRandom secRand = new SecureRandom();

    static {
        secRand.nextLong(); //seed in static space
        r.setSeed(secRand.nextLong()); //also seed our PRNG
    }

    public static int nextInt() {
        return r.nextInt();
    }

    public static byte nextNibble() {
        return (byte) (nextInt() & 0xF);
    }

    public static SecureRandom getSecureRandom() {
        final byte[] seed = new byte[32];
        secRand.nextBytes(seed);
        return new SecureRandom(seed);
    }
}
