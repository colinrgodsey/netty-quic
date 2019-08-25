package com.colingodsey.quic.crypto.context;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import at.favre.lib.crypto.HKDF;

import com.colingodsey.quic.packet.components.ConnectionID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TLS_AES_128_GCM_SHA256 extends CryptoContext {
    static final int GCM_BITS = 128;
    static final HKDF hkdf = HKDF.fromHmacSha256();

    final SecretKey wPayload;
    final SecretKey wHP;
    final IvParameterSpec wIV;
    final Cipher wPayloadCipher;
    final Cipher wHeaderCipher;

    final SecretKey rPayload;
    final SecretKey rHP;
    final IvParameterSpec rIV;

    TLS_AES_128_GCM_SHA256(ConnectionID connectionID, boolean isServer) throws GeneralSecurityException {
        this(new SecretKeySpec(
                hkdf.extract(QUIC_V1_INITIAL_SALT, connectionID.getBytes()), "HKDF"), isServer);
    }

    private TLS_AES_128_GCM_SHA256(SecretKey masterSecret, boolean isServer) throws GeneralSecurityException {
        this(
                expandKey(masterSecret, !isServer ? QUIC_CLIENT_IN_LABEL : QUIC_SERVER_IN_LABEL),
                expandKey(masterSecret, isServer  ? QUIC_CLIENT_IN_LABEL : QUIC_SERVER_IN_LABEL)
        );
    }

    TLS_AES_128_GCM_SHA256(SecretKey writeKey, SecretKey readKey) throws GeneralSecurityException {
        wPayload = expandKey(writeKey, QUIC_KEY_LABEL);
        wHP = expandKey(writeKey, QUIC_HP_LABEL);
        wIV = expandIV(writeKey, QUIC_IV_LABEL);
        wPayloadCipher = Cipher.getInstance("AES/GCM/NoPadding");
        wHeaderCipher = Cipher.getInstance("AES/ECB/NoPadding");
        wHeaderCipher.init(Cipher.ENCRYPT_MODE, wHP);

        rPayload = expandKey(readKey, QUIC_KEY_LABEL);
        rHP = expandKey(readKey, QUIC_HP_LABEL);
        rIV = expandIV(readKey, QUIC_IV_LABEL);
    }

    AlgorithmParameterSpec createIV(int packetNum, boolean isWrite) {
        final byte[] nonce = isWrite ? wIV.getIV() : rIV.getIV();
        final byte[] pnBytes = BigInteger.valueOf(packetNum).toByteArray();
        final int offset = nonce.length - pnBytes.length;
        for (int i = 0 ; i < pnBytes.length ; i++) {
            nonce[offset + i] ^= pnBytes[i];
        }
        return new GCMParameterSpec(GCM_BITS, nonce);
    }

    SecretKey getWPayloadKey() {
        return wPayload;
    }

    Cipher getWPayloadCipher() {
        return wPayloadCipher;
    }

    Cipher getWHeaderCipher() {
        return wHeaderCipher;
    }

    protected static IvParameterSpec expandIV(SecretKey key, Label label) {
        return new IvParameterSpec(hkdf.expand(key, label.bytes, label.length));
    }

    protected static SecretKey expandKey(SecretKey key, Label label) {
        return new SecretKeySpec(hkdf.expand(key, label.bytes, label.length), "AES");
    }
}
