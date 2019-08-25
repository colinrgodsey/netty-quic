package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import com.colingodsey.quic.packet.components.ConnectionID;
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

    abstract AlgorithmParameterSpec createIV(int packetNum, boolean isWrite);
    abstract SecretKey getWPayloadKey();
    abstract Cipher getWPayloadCipher();
    abstract Cipher getWHeaderCipher();

    public void encryptPayload(ByteBuffer header, ByteBuffer payload, int packetNumber, ByteBuffer output) {
        final Cipher cipher = getWPayloadCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, getWPayloadKey(), createIV(packetNumber, true));
            cipher.updateAAD(header);
            cipher.doFinal(payload, output);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptPayload(byte[] header, byte[] payload, int packetNumber) {
        final Cipher cipher = getWPayloadCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, getWPayloadKey(), createIV(packetNumber, true));
            cipher.updateAAD(header);
            return cipher.doFinal(payload);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //TODO: needs padding again?
    public byte[] headerProtectMask(ByteBuffer encryptedPayload, int pnLength) {
        final Cipher cipher = getWHeaderCipher();
        final byte[] out = new byte[cipher.getOutputSize(SAMPLE_SIZE)];
        final ByteBuffer sample = encryptedPayload.slice();

        sample.position(4 - pnLength).limit((4 + SAMPLE_SIZE) - pnLength);
        try {
            cipher.doFinal(sample, ByteBuffer.wrap(out));
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(byte[] encryptedPayload, int pnLength) {
        return headerProtectMask(ByteBuffer.wrap(encryptedPayload), pnLength);
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
