package com.colingodsey.quic.crypto;

import static com.colingodsey.quic.utils.Utils.h2ba;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.components.Header;
import com.colingodsey.quic.packet.components.LongHeader;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class InitialSampleTest {
    /*final byte[] testPacketFull1 = h2ba("" + //contains handshake + 1RTT packet
              "eaff000014c50f1ab16f5c84e23a713662040ad72145f75118c221bae2401675"
            + "4f8558fffab058950769516a1d5b8ea5fb716e5b97460f1ab16f5c84e23a7136"
            + "62040ad7210e2daf474b9e77f88510cfdb1a1877f5dc3ac986d7d94a98a161e9"
            + "7bc121bf157dcadd6396ea34b194c531f58ba4aa64ba0655f3e489be8ac6c274"
            + "4f9b14356b6e9e881a8b4bc3538fd3000162172ff89eba521a3641dce5179f68"
            + "528d8a43ce0b12d651fecc091729093bb3b0dc6110d0ae53075434c961908c37"
            + "260830beb02213ff34e85cb109763c14ff4b852a64b38c5fb4c4d6aebc8830cc"
            + "0053803e0e26d7f3f197e128c28d041fcda99adbd282b17e1a9efee8460af824"
            + "1d42d788c05361c2e7de658c3ad0d17bf04bb3aae3a9863d5a03");*/ // ??
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
        final DerivedSecrets secrets = new DerivedSecrets(header.sourceID);

        //i dont trust this, but lets use it for now
        BigInteger nonceInt = new BigInteger(secrets.clientSecrets.iv).xor(BigInteger.valueOf(2)); // packet num

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec skeySpec = new SecretKeySpec(secrets.clientSecrets.key, "AES");
        AlgorithmParameterSpec iv = new GCMParameterSpec(128, nonceInt.toByteArray());

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        cipher.updateAAD(testHeader);

        byte[] output = cipher.doFinal(Arrays.copyOf(testPayload, 1163));

        assertArrayEquals(
                protectedSample,
                Arrays.copyOf(output, protectedSample.length));
    }
}
