package com.colingodsey.quic.crypto.context;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import at.favre.lib.crypto.HKDF;

import com.colingodsey.quic.packet.components.ConnectionID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TLS_AES_128_GCM_SHA256 extends CryptoContext {
    static final int HASH_BYTES = 32;
    static final int GCM_BITS = 128;
    static final HKDF hkdf = HKDF.fromHmacSha256();

    final EndpointFunctions clientKeys;
    final EndpointFunctions serverKeys;

    /**
     * Crypto context used for the initial phase, derived from the connection ID.
     *
     * @param connectionID ID used to derive the crypto keys.
     * @throws GeneralSecurityException
     */
    public TLS_AES_128_GCM_SHA256(ConnectionID connectionID) throws GeneralSecurityException {
        this(hkdf.extract(QUIC_V1_INITIAL_SALT, connectionID.getBytes()));
    }

    /**
     * Crypto context used for the handshake and 1-RTT phases.
     *
     * For the handshake phase, the handshake secret from the TLS context should be used.
     * For the 1-RTT phase, the master secret from the TLS context should be used.
     *
     * @param masterSecret Secret key obtained from the appropriate TLS phase.
     * @throws GeneralSecurityException
     */
    public TLS_AES_128_GCM_SHA256(SecretKey masterSecret) throws GeneralSecurityException {
        this(masterSecret.getEncoded());
    }

    TLS_AES_128_GCM_SHA256(byte[] masterSecret) throws GeneralSecurityException {
        clientKeys = new EndpointFunctions(hkdf.expand(masterSecret, CLIENT_IN_LABEL, HASH_BYTES));
        serverKeys = new EndpointFunctions(hkdf.expand(masterSecret, SERVER_IN_LABEL, HASH_BYTES));
    }

    public EndpointFunctions getClient() {
        return clientKeys;
    }

    public EndpointFunctions getServer() {
        return serverKeys;
    }

    //TODO: abstract these methods out
    class EndpointFunctions extends CryptoContext.EndpointFunctions {
        final SecretKey key;
        final SecretKey hpKey;
        final IvParameterSpec iv;
        final Cipher payloadCipher;
        final Cipher headerCipher;

        EndpointFunctions(byte[] secret) throws GeneralSecurityException {
            iv = new IvParameterSpec(hkdf.expand(secret, IV_LABEL, IV_LENGTH));
            key = new SecretKeySpec(hkdf.expand(secret, KEY_LABEL, KEY_LENGTH), "AES");
            hpKey = new SecretKeySpec(hkdf.expand(secret, HP_LABEL, KEY_LENGTH), "AES");
            payloadCipher = Cipher.getInstance("AES/GCM/NoPadding");
            headerCipher = Cipher.getInstance("AES/ECB/NoPadding");
            headerCipher.init(Cipher.ENCRYPT_MODE, hpKey);
        }

        AlgorithmParameterSpec createIV(int packetNum) {
            final byte[] nonce = iv.getIV();
            final byte[] pnBytes = BigInteger.valueOf(packetNum).toByteArray();
            final int offset = nonce.length - pnBytes.length;
            for (int i = 0 ; i < pnBytes.length ; i++) {
                nonce[offset + i] ^= pnBytes[i];
            }
            return new GCMParameterSpec(GCM_BITS, nonce);
        }

        SecretKey getKey() {
            return key;
        }

        Cipher getPayloadCipher() {
            return payloadCipher;
        }

        Cipher getHeaderCipher() {
            return headerCipher;
        }
    }
}
