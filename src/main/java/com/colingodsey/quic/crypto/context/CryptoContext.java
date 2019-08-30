package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.util.ReferenceCountUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.header.Header;
import com.colingodsey.quic.packet.header.ShortHeader;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public abstract class CryptoContext {
    static final byte[] QUIC_V1_INITIAL_SALT = h2ba("c3eef712c72ebb5a11a7d2432bb46365bef9f502");

    static final Label QUIC_CLIENT_IN_LABEL = new Label("client in", 32);
    static final Label QUIC_SERVER_IN_LABEL = new Label("server in", 32);
    static final Label QUIC_KEY_LABEL = new Label("quic key", 16);
    static final Label QUIC_IV_LABEL = new Label("quic iv", 12);
    static final Label QUIC_HP_LABEL = new Label("quic hp", 16);

    static final int SAMPLE_SIZE = 16;

    /**
     * Crypto context used for the initial phase, derived from the connection ID.
     *
     * @param connectionID ID used to derive the crypto keys.
     * @throws GeneralSecurityException
     */
    public static CryptoContext createInitial(String cipherSuite, ConnectionID connectionID, boolean isServer)
            throws GeneralSecurityException {
        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
                return new TLS_AES_128_GCM_SHA256(connectionID, isServer);
            default:
                throw new NoSuchAlgorithmException(cipherSuite);
        }
    }

    /**
     * Crypto context used for the handshake and 1-RTT phases.
     *
     * For the handshake phase, the handshake secret from the TLS context should be used.
     * For the 1-RTT phase, the master secret from the TLS context should be used.
     *
     * @param writeKey Secret write key negotiated by TLS.
     * @param readKey Secret read key negotiated by TLS.
     * @throws GeneralSecurityException
     */
    public static CryptoContext createKeyed(String cipherSuite, SecretKey writeKey, SecretKey readKey) throws GeneralSecurityException {
        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
                return new TLS_AES_128_GCM_SHA256(writeKey, readKey);
            default:
                throw new NoSuchAlgorithmException(cipherSuite);
        }
    }

    abstract AlgorithmParameterSpec createIV(int packetNum, boolean isEncrypt);
    abstract SecretKey getWPayloadKey();
    abstract Cipher getPayloadCipher();
    abstract Cipher getWHeaderCipher();
    abstract SecretKey getRPayloadKey();
    abstract Cipher getRHeaderCipher();

    public int payloadCrypto(ByteBuffer header, ByteBuffer payload, int packetNumber, ByteBuffer out, boolean isEncrypt) {
        final Cipher cipher = getPayloadCipher();
        try {
            cipher.init(
                    isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    isEncrypt ? getWPayloadKey() : getRPayloadKey(),
                    createIV(packetNumber, isEncrypt)
            );
            cipher.updateAAD(header);
            return cipher.doFinal(payload, out);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(ByteBuf ePayload, int index, int pnLength, boolean isEncrypt) {
        final Cipher cipher = isEncrypt ? getWHeaderCipher() : getRHeaderCipher();
        final byte[] out = new byte[cipher.getOutputSize(SAMPLE_SIZE)];
        try {
            cipher.doFinal(
                    ePayload.nioBuffer(index + 4 - pnLength, SAMPLE_SIZE),
                    ByteBuffer.wrap(out)
            );
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(byte[] encryptedPayload, int pnLength, boolean isEncrypt) {
        return headerProtectMask(Unpooled.wrappedBuffer(encryptedPayload), 0, pnLength, isEncrypt);
    }

    protected void encrypt(Packet packet, ByteBuf out) {
        final int head = out.writerIndex();
        final Header header = packet.getHeader();
        header.write(out);

        final int headerLength = out.readableBytes();
        final boolean isShort = header instanceof ShortHeader;
        final int pnIndex = head + headerLength - header.getPacketNumberBytes();

        out.ensureWritable(packet.getPayload().readableBytes() + 16);

        final int written = payloadCrypto(
                out.nioBuffer(head, headerLength),
                packet.getPayload().nioBuffer(),
                header.getPacketNumber(),
                out.nioBuffer(out.writerIndex(), out.writableBytes()), true);
        out.writerIndex(out.writerIndex() + written);

        final byte[] mask = headerProtectMask(
                out, head + headerLength,
                header.getPacketNumberBytes(), true);

        xor(out, 0, mask[0] & (isShort ? 0x1F : 0xF));
        for (int i = 0 ; i < header.getPacketNumberBytes() ; i++) {
            xor(out, pnIndex + i, mask[1 + i]);
        }
    }

    //decrypt in place
    protected Packet decrypt(ByteBuf in) {
        final int head = in.readerIndex();
        final boolean isShort = Header.getType(in) == null;
        final int preHeaderLength = Header.getHeaderLength(in, false) + 4;
        final byte[] mask = headerProtectMask(
                in, head + preHeaderLength, 4, false);

        //unmask first byte so we can get the real packetNumberBytes
        xor(in, head, mask[0] & (isShort ? 0x1F : 0xF));

        final int headerLength = Header.getHeaderLength(in, true);
        final int pnLength = Header.getPacketNumberBytes(in);
        final int pnIndex = head + headerLength - pnLength;

        for (int i = 0 ; i < pnLength ; i++) {
            xor(in, pnIndex + i, mask[1 + i]);
        }

        final Header header = Header.read(in.readerIndex(head));
        final int ePayloadLength = in.readableBytes();
        assert (in.readerIndex() - head) == headerLength;

        final int written = payloadCrypto(
                in.nioBuffer(head, headerLength),
                in.nioBuffer(head + headerLength, ePayloadLength),
                header.getPacketNumber(),
                in.nioBuffer(head, ePayloadLength), false);
        in.skipBytes(ePayloadLength);

        return new Packet(header, in.slice(head, written));
    }

    static final void xor(ByteBuf buf, int index, int value) {
        buf.setByte(index, buf.getUnsignedByte(index) ^ (value & 0xFF));
    }

    static class Label {
        static final String prefix = "tls13 ";
        static final byte[] context = new byte[] {0};

        final byte[] bytes;
        final int length;

        Label(String label, int length) {
            bytes = new byte[2 + 1 + prefix.length() + label.length() + context.length];
            this.length = length;

            final ByteBuf writer = Unpooled.wrappedBuffer(bytes).clear();
            writer.writeShort(length);
            writer.writeByte(prefix.length() + label.length());
            writer.writeCharSequence(prefix, StandardCharsets.US_ASCII);
            writer.writeCharSequence(label, StandardCharsets.US_ASCII);
            writer.writeBytes(context);
            assert writer.writableBytes() == 0;
        }
    }
}
