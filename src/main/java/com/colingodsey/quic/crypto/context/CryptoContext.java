package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

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

    public void encryptPayload(ByteBuf header, ByteBuf payload, int packetNumber, ByteBuf out) {
        final Cipher cipher = getPayloadCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, getWPayloadKey(), createIV(packetNumber, true));
            cipher.updateAAD(header.nioBuffer());
            out.ensureWritable(cipher.getOutputSize(payload.readableBytes()));
            final int length = cipher.doFinal(payload.nioBuffer(),
                    out.nioBuffer(out.writerIndex(), out.writableBytes()));
            out.writerIndex(out.writerIndex() + length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void decryptPayload(ByteBuf header, ByteBuf payload, int packetNumber, ByteBuf out) {
        final Cipher cipher = getPayloadCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, getRPayloadKey(), createIV(packetNumber, false));
            cipher.updateAAD(header.nioBuffer());
            out.ensureWritable(cipher.getOutputSize(payload.readableBytes()));
            final int length = cipher.doFinal(payload.nioBuffer(),
                    out.nioBuffer(out.writerIndex(), out.writableBytes()));
            out.writerIndex(out.writerIndex() + length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(ByteBuf encryptedPayload, int pnLength, boolean isEncrypt) {
        final Cipher cipher = isEncrypt ? getWHeaderCipher() : getRHeaderCipher();
        final byte[] out = new byte[cipher.getOutputSize(SAMPLE_SIZE)];
        final ByteBuf sample = encryptedPayload.slice(
                encryptedPayload.readerIndex() + 4 - pnLength, SAMPLE_SIZE);
        try {
            cipher.doFinal(sample.nioBuffer(), ByteBuffer.wrap(out));
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(byte[] encryptedPayload, int pnLength, boolean isEncrypt) {
        return headerProtectMask(Unpooled.wrappedBuffer(encryptedPayload), pnLength, isEncrypt);
    }

    protected void encrypt(Packet packet, ByteBuf out) {
        final int readerIndex = out.readerIndex();
        final Header header = packet.getHeader();
        header.write(out);
        final boolean isShort = header instanceof ShortHeader;
        final int headerOffset = out.writerIndex();
        final int pnOffset = headerOffset - header.getPacketNumberBytes();

        encryptPayload(out, packet.getPayload(), header.getPacketNumber(), out);
        final byte[] mask = headerProtectMask(out.readerIndex(headerOffset),
                header.getPacketNumberBytes(), true);
        out.readerIndex(readerIndex);
        xor(out, 0, mask[0] & (isShort ? 0x1F : 0xF));
        for (int i = 0 ; i < header.getPacketNumberBytes() ; i++) {
            xor(out, pnOffset + i, mask[1 + i]);
        }
    }

    protected Packet decrypt(ByteBuf in) {
        final int readerIndex = in.readerIndex();
        final boolean isShort = Header.getType(in) == null;
        final int preHeaderLength = Header.getHeaderLength(in, false) + 4;
        final byte[] mask = headerProtectMask(
                in.readerIndex(readerIndex + preHeaderLength), 4, false);

        xor(in.readerIndex(readerIndex), 0, mask[0] & (isShort ? 0x1F : 0xF));

        final int headerLength = Header.getHeaderLength(in, true);
        final int pnLength = Header.getPacketNumberBytes(in);
        final int pnOffset = headerLength - pnLength;

        for (int i = 0 ; i < pnLength ; i++) {
            xor(in, pnOffset + i, mask[1 + i]);
        }

        final Header header = Header.read(in.readerIndex(readerIndex));
        final ByteBuf payload = in.alloc().ioBuffer(in.readableBytes() + 100);
        decryptPayload(
                in.slice(readerIndex, in.readerIndex()),
                in, header.getPacketNumber(), payload);

        return new Packet(header, payload);
    }

    static final void xor(ByteBuf buf, int offset, int value) {
        final int x = buf.getUnsignedByte(buf.readerIndex() + offset);
        buf.setByte(buf.readerIndex() + offset, x ^ (value & 0xFF));
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
