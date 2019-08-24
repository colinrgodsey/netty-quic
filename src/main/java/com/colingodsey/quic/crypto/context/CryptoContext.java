package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;

import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public abstract class CryptoContext {
    static final byte[] QUIC_V1_INITIAL_SALT = h2ba("c3eef712c72ebb5a11a7d2432bb46365bef9f502");

    static final byte[] CLIENT_IN_LABEL = h2ba("00200f746c73313320636c69656e7420696e00"); //"client in"
    static final byte[] SERVER_IN_LABEL = h2ba("00200f746c7331332073657276657220696e00"); //"server in"
    static final byte[] KEY_LABEL = h2ba("00100e746c7331332071756963206b657900"); //"quic key"
    static final byte[] IV_LABEL = h2ba("000c0d746c733133207175696320697600"); //"quic iv"
    static final byte[] HP_LABEL = h2ba("00100d746c733133207175696320687000"); //"quic hp"

    static final int KEY_LENGTH = 16;
    static final int IV_LENGTH = 12;
    static final int SAMPLE_SIZE = 16;

    abstract public EndpointFunctions getClient();
    abstract public EndpointFunctions getServer();

    abstract public class EndpointFunctions {
        abstract AlgorithmParameterSpec createIV(int packetNum);
        abstract SecretKey getKey();
        abstract Cipher getPayloadCipher();
        abstract Cipher getHeaderCipher();

        public void encryptPayload(ByteBuffer header, ByteBuffer payload, int packetNumber, ByteBuffer output) {
            final Cipher cipher = getPayloadCipher();
            try {
                cipher.init(Cipher.ENCRYPT_MODE, getKey(), createIV(packetNumber));
                cipher.updateAAD(header);
                cipher.doFinal(payload, output);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public byte[] encryptPayload(byte[] header, byte[] payload, int packetNumber) {
            final Cipher cipher = getPayloadCipher();
            try {
                cipher.init(Cipher.ENCRYPT_MODE, getKey(), createIV(packetNumber));
                cipher.updateAAD(header);
                return cipher.doFinal(payload);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        //TODO: needs padding again
        public byte[] headerProtectMask(ByteBuffer encryptedPayload, int pnLength) {
            final Cipher cipher = getHeaderCipher();
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
    }
}
