package com.colingodsey.quic.crypto;

import static com.colingodsey.quic.utils.Utils.h2ba;
import static org.junit.Assert.assertArrayEquals;

import io.netty.buffer.Unpooled;

import java.util.Arrays;

import com.colingodsey.quic.crypto.context.Context;
import com.colingodsey.quic.crypto.context.TLS_AES_128_GCM_SHA256;
import com.colingodsey.quic.packet.components.Header;
import com.colingodsey.quic.packet.components.LongHeader;

import org.junit.Test;

public class InitialSampleTest {
    final byte[] testHeader = h2ba("" +
              "c3ff000017088394c8f03e5157080000449e00000002");
    final byte[] testPayload = h2ba("" +
              "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
            + "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
            + "736572766572ff01000100000a00140012001d00170018001901000101010201"
            + "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
            + "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
            + "05030603020308040805080604010501060102010402050206020202002d0002"
            + "0101001c00024001");
    final byte[] protectedSample = h2ba("535064a4268a0d9d7b1c9d250ae35516");

    @Test
    public void header() throws Exception {
        final Header header = Header.read(Unpooled.wrappedBuffer(testHeader));
        System.out.println(header);
    }

    @Test
    public void clientEncrypt() throws Exception {
        final LongHeader header = (LongHeader) Header.read(Unpooled.wrappedBuffer(testHeader));
        final Context ctx = new TLS_AES_128_GCM_SHA256(header.sourceID);
        final byte[] output = ctx.getClient().encryptPayload(testHeader, testPayload, 2);

        assertArrayEquals(
                protectedSample,
                Arrays.copyOf(output, protectedSample.length));
    }
}
