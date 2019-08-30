package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import java.util.Arrays;
import java.util.Random;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.header.Header;
import com.colingodsey.quic.packet.header.InitialHeader;
import com.colingodsey.quic.packet.header.LongHeader;
import com.colingodsey.quic.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class CryptoContextTest {
    final byte[] testPayloadPadded = h2ba(""
            + "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
            + "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
            + "736572766572ff01000100000a00140012001d00170018001901000101010201"
            + "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
            + "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
            + "05030603020308040805080604010501060102010402050206020202002d0002"
            + "0101001c00024001000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000");
    final byte[] protectedSample = h2ba("535064a4268a0d9d7b1c9d250ae35516");
    final byte[] testHeader = h2ba(""
            + "c3ff000017088394c8f03e5157080000449e00000002");
    final byte[] testHeaderReal = h2ba(""
            + "c0ff000017088394c8f03e5157080000449e02");
    final byte[] testPayload = h2ba(""
            + "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
            + "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
            + "736572766572ff01000100000a00140012001d00170018001901000101010201"
            + "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
            + "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
            + "05030603020308040805080604010501060102010402050206020202002d0002"
            + "0101001c00024001");
    final byte[] testEncryptedPacket = h2ba(""
            + "c0ff000017088394c8f03e5157080000449e3b343aa8535064a4268a0d9d7b1c"
            + "9d250ae355162276e9b1e3011ef6bbc0ab48ad5bcc2681e953857ca62becd752"
            + "4daac473e68d7405fbba4e9ee616c87038bdbe908c06d9605d9ac49030359eec"
            + "b1d05a14e117db8cede2bb09d0dbbfee271cb374d8f10abec82d0f59a1dee29f"
            + "e95638ed8dd41da07487468791b719c55c46968eb3b54680037102a28e53dc1d"
            + "12903db0af5821794b41c4a93357fa59ce69cfe7f6bdfa629eef78616447e1d6"
            + "11c4baf71bf33febcb03137c2c75d25317d3e13b684370f668411c0f00304b50"
            + "1c8fd422bd9b9ad81d643b20da89ca0525d24d2b142041cae0af205092e43008"
            + "0cd8559ea4c5c6e4fa3f66082b7d303e52ce0162baa958532b0bbc2bc785681f"
            + "cf37485dff6595e01e739c8ac9efba31b985d5f656cc092432d781db95221724"
            + "87641c4d3ab8ece01e39bc85b15436614775a98ba8fa12d46f9b35e2a55eb72d"
            + "7f85181a366663387ddc20551807e007673bd7e26bf9b29b5ab10a1ca87cbb7a"
            + "d97e99eb66959c2a9bc3cbde4707ff7720b110fa95354674e395812e47a0ae53"
            + "b464dcb2d1f345df360dc227270c750676f6724eb479f0d2fbb6124429990457"
            + "ac6c9167f40aab739998f38b9eccb24fd47c8410131bf65a52af841275d5b3d1"
            + "880b197df2b5dea3e6de56ebce3ffb6e9277a82082f8d9677a6767089b671ebd"
            + "244c214f0bde95c2beb02cd1172d58bdf39dce56ff68eb35ab39b49b4eac7c81"
            + "5ea60451d6e6ab82119118df02a586844a9ffe162ba006d0669ef57668cab38b"
            + "62f71a2523a084852cd1d079b3658dc2f3e87949b550bab3e177cfc49ed190df"
            + "f0630e43077c30de8f6ae081537f1e83da537da980afa668e7b7fb25301cf741"
            + "524be3c49884b42821f17552fbd1931a813017b6b6590a41ea18b6ba49cd48a4"
            + "40bd9a3346a7623fb4ba34a3ee571e3c731f35a7a3cf25b551a680fa68763507"
            + "b7fde3aaf023c50b9d22da6876ba337eb5e9dd9ec3daf970242b6c5aab3aa4b2"
            + "96ad8b9f6832f686ef70fa938b31b4e5ddd7364442d3ea72e73d668fb0937796"
            + "f462923a81a47e1cee7426ff6d9221269b5a62ec03d6ec94d12606cb485560ba"
            + "b574816009e96504249385bb61a819be04f62c2066214d8360a2022beb316240"
            + "b6c7d78bbe56c13082e0ca272661210abf020bf3b5783f1426436cf9ff418405"
            + "93a5d0638d32fc51c5c65ff291a3a7a52fd6775e623a4439cc08dd25582febc9"
            + "44ef92d8dbd329c91de3e9c9582e41f17f3d186f104ad3f90995116c682a2a14"
            + "a3b4b1f547c335f0be710fc9fc03e0e587b8cda31ce65b969878a4ad4283e6d5"
            + "b0373f43da86e9e0ffe1ae0fddd3516255bd74566f36a38703d5f34249ded1f6"
            + "6b3d9b45b9af2ccfefe984e13376b1b2c6404aa48c8026132343da3f3a33659e"
            + "c1b3e95080540b28b7f3fcd35fa5d843b579a84c089121a60d8c1754915c344e"
            + "eaf45a9bf27dc0c1e78416169122091313eb0e87555abd706626e557fc36a04f"
            + "cd191a58829104d6075c5594f627ca506bf181daec940f4a4f3af0074eee89da"
            + "acde6758312622d4fa675b39f728e062d2bee680d8f41a597c262648bb18bcfc"
            + "13c8b3d97b1a77b2ac3af745d61a34cc4709865bac824a94bb19058015e4e42d"
            + "c9be6c7803567321829dd85853396269");

    final String connIDStr = "8394c8f03e515708";
    final ConnectionID connID = new ConnectionID(h2ba(connIDStr));

    @Test
    public void secretsTest() throws Exception {
        final TLS_AES_128_GCM_SHA256 secrets = new TLS_AES_128_GCM_SHA256(connID, false);

        assertArrayEquals(
                h2ba(connIDStr),
                connID.getBytes());

        /*assertArrayEquals(
                h2ba("af7fd7efebd21878ff66811248983694"),
                secrets.wKey.getEncoded());*/
        assertArrayEquals(
                h2ba("8681359410a70bb9c92f0420"),
                secrets.wIV.getIV());
        /*assertArrayEquals(
                h2ba("a980b8b4fb7d9fbc13e814c23164253d"),
                secrets.wHP.getEncoded());*/

        /*assertArrayEquals(
                h2ba("5d51da9ee897a21b2659ccc7e5bfa577"),
                secrets.readKeys.key.getEncoded());*/
        assertArrayEquals(
                h2ba("5e5ae651fd1e8495af13508b"),
                secrets.rIV.getIV());
        /*assertArrayEquals(
                h2ba("a8ed82e6664f865aedf6106943f95fb8"),
                secrets.rHP.getEncoded());*/
    }

    @Test
    public void clientEncryptRaw() throws Exception {
        final LongHeader header = (LongHeader) Header.read(Unpooled.wrappedBuffer(testHeader));
        final TLS_AES_128_GCM_SHA256 ctx = new TLS_AES_128_GCM_SHA256(header.sourceID, false);
        final int pnLength = 1 + (testHeader[0] & 0x3); //4
        final int packetNumber = 2;

        /*final byte[] aad = new byte[testHeader.length + 2 + pnLength];
        final ByteBuf aadBuf = Unpooled.wrappedBuffer(aad).writerIndex(0);
        aadBuf.writeBytes(testHeader);
        aadBuf.writeShort(0x4000 | (pnLength + testPayload.length + 16));
        Packet.writeFixedLengthInt(packetNumber, pnLength, aadBuf);*/

        final byte[] ePayload = Utils.createBytes(out -> {
            int written = ctx.payloadCrypto(
                    Unpooled.wrappedBuffer(testHeader).nioBuffer(),
                    Unpooled.buffer().writeBytes(testPayload).writeBytes(new byte[800]).nioBuffer(),
                    packetNumber,
                    out.nioBuffer(0, 1200), true);
            out.writerIndex(out.writerIndex() + written);
        }, 1200);

        //payload needs to be 1163 before encrypting
        /*Assert.assertArrayEquals(
                testPayloadPadded,
                Utils.concat(testHeader, Utils.concat(testPayload, new byte[940])));*/

        assertArrayEquals(
                protectedSample,
                Arrays.copyOf(ePayload, protectedSample.length));

        byte[] mask = ctx.headerProtectMask(ePayload, pnLength, true);

        assertArrayEquals(h2ba("833b343aaa87038e612d933506d446a0"), mask);

        byte[] encryptedHeader = testHeader.clone();

        //encrypt meta flags
        int firstByteMask = (header.isLong() ? 0x0F : 0x1F);
        encryptedHeader[0] ^= mask[0] & firstByteMask;

        assertEquals(0xc0, encryptedHeader[0] & 0xFF);

        //encrypt packet number
        final int pnOffset = testHeader.length - pnLength;
        for (int i = 0 ; i < 4 ; i++) {
            encryptedHeader[pnOffset + i] ^= mask[1 + i];
        }

        assertArrayEquals(
                h2ba("c0ff000017088394c8f03e5157080000449e3b343aa8"),
                encryptedHeader);

        //assertArrayEquals(testEncryptedPacket, Utils.concat(encryptedHeader, ePayload));
    }

    @Test
    public void testDecrypt() throws Exception {
        final ByteBuf testPacket = Unpooled.wrappedBuffer(testEncryptedPacket);
        final TLS_AES_128_GCM_SHA256 clientCtx = new TLS_AES_128_GCM_SHA256(connID, false);
        final TLS_AES_128_GCM_SHA256 serverCtx = new TLS_AES_128_GCM_SHA256(connID, true);

        final ByteBuf out = Unpooled.buffer();

        Packet packet = serverCtx.decrypt(testPacket);
        clientCtx.encrypt(packet, out);

        assertArrayEquals(
                testPayloadPadded,
                Utils.createBytes(buf ->
                        buf.writeBytes(packet.getPayload().duplicate()), 100)
        );
    }

    @Test
    public void testEncrypt() throws Exception {
        final TLS_AES_128_GCM_SHA256 clientCtx = new TLS_AES_128_GCM_SHA256(connID, false);
        final TLS_AES_128_GCM_SHA256 serverCtx = new TLS_AES_128_GCM_SHA256(connID, true);

        final ByteBuf out = Unpooled.buffer();
        final Packet testPacket = new Packet(
                Header.read(Unpooled.wrappedBuffer(testHeader)),
                Unpooled.wrappedBuffer(testPayloadPadded)
        );

        clientCtx.encrypt(testPacket, out);

        assertArrayEquals(
                testEncryptedPacket,
                Utils.createBytes(buf ->
                        buf.writeBytes(out.duplicate()), 100)
        );

        final Packet testPacketOut = serverCtx.decrypt(out.slice());

        assertArrayEquals(
                testPayloadPadded,
                Utils.createBytes(buf ->
                        buf.writeBytes(testPacketOut.getPayload().duplicate()), 100)
        );
    }

    @Test
    public void contextStateTest() throws Exception {
        final TLS_AES_128_GCM_SHA256 clientCtx = new TLS_AES_128_GCM_SHA256(connID, false);
        final TLS_AES_128_GCM_SHA256 serverCtx = new TLS_AES_128_GCM_SHA256(connID, true);

        for (int i = 0 ; i < 10 ; i++) {
            final ByteBuf out = Unpooled.buffer();
            final Packet testPacket = new Packet(
                    new InitialHeader(0xff000017, connID, ConnectionID.EMPTY,
                            new byte[0], testPayloadPadded.length, i),
                    Unpooled.wrappedBuffer(testPayloadPadded)
            );

            clientCtx.encrypt(testPacket, out);
            serverCtx.decrypt(out.slice());
        }
    }

    @Test
    public void testEncryptRandomPN() throws Exception {
        final TLS_AES_128_GCM_SHA256 clientCtx = new TLS_AES_128_GCM_SHA256(connID, false);
        final TLS_AES_128_GCM_SHA256 serverCtx = new TLS_AES_128_GCM_SHA256(connID, true);
        final Random r = new Random(96673);
        final ByteBuf out = Unpooled.buffer();

        for (int i = 0 ; i < 1000 ; i++) {
            out.clear();
            final int pn = r.nextInt() >>> 1;
            final Packet testPacket = new Packet(
                    new InitialHeader(0xff000017, connID, ConnectionID.EMPTY,
                            new byte[0], testPayloadPadded.length, pn),
                    Unpooled.wrappedBuffer(testPayloadPadded)
            );

            clientCtx.encrypt(testPacket, out);
            final Packet testPacketOut = serverCtx.decrypt(out);

            assertArrayEquals(
                    testPayloadPadded,
                    Utils.createBytes(buf ->
                            buf.writeBytes(testPacketOut.getPayload().duplicate()), 100)
            );
            assertEquals(pn, testPacketOut.getHeader().getPacketNumber());
        }
    }

    @Test
    public void header() throws Exception {
        final Header header = Header.read(Unpooled.wrappedBuffer(testHeader));
        System.out.println(header);
    }

    @Test
    public void maskTest() throws Exception {
        byte[] sample = h2ba("da5c83732bb0d8c945563b6ba1a57a5f");
        SecretKeySpec skeySpec = new SecretKeySpec(h2ba("3271d12d0c6e3faac0e1e8a29294146c"), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        assertArrayEquals(
                h2ba("0ed450ec84"),
                Arrays.copyOf(cipher.doFinal(sample), 5));
    }

    //TODO: really hard to test the exact padding needed here
    /*@Test
    public void clientEncrypt() throws Exception {
        byte[] bulk = Utils.concat(testHeader, testPayload);
        Initial initial = new Initial(Unpooled.wrappedBuffer(bulk));
        final TLS_AES_128_GCM_SHA256 ctx = new TLS_AES_128_GCM_SHA256(initial.getHeader().sourceID);

        byte[] encrypted = initial.produceEncrypted(ctx.getClient());

        assertArrayEquals(testEncryptedPacket, encrypted);
    }*/
}
