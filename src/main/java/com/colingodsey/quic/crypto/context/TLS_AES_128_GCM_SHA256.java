package com.colingodsey.quic.crypto.context;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import com.colingodsey.quic.crypto.DerivedSecrets;
import com.colingodsey.quic.packet.components.ConnectionID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//not thread safe
public class TLS_AES_128_GCM_SHA256 extends Context {
    final ConnectionID connectionID;
    final Cipher headerCipher;
    final KeyStack clientKeys;
    final KeyStack serverKeys;

    public TLS_AES_128_GCM_SHA256(ConnectionID connectionID)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.connectionID = connectionID;
        this.headerCipher = Cipher.getInstance("AES/GCM/NoPadding");
        final DerivedSecrets secrets = new DerivedSecrets(connectionID);
        clientKeys = new KeyStack(secrets.clientSecrets);
        serverKeys = new KeyStack(secrets.serverSecrets);
    }

    public KeyStack getClient() {
        return clientKeys;
    }

    public KeyStack getServer() {
        return serverKeys;
    }

    class KeyStack extends IKeyStack {
        final SecretKey key;
        final DerivedSecrets.PacketSecrets secrets;

        KeyStack(DerivedSecrets.PacketSecrets secrets) {
            key = new SecretKeySpec(secrets.key, "AES");
            this.secrets = secrets;
        }

        public byte[] encryptPayload(byte[] header, byte[] payload, int packetNumber)
                throws InvalidAlgorithmParameterException, InvalidKeyException,
                BadPaddingException, IllegalBlockSizeException {
            headerCipher.init(Cipher.ENCRYPT_MODE, key, getAlgoParam(packetNumber));
            headerCipher.updateAAD(header);
            return headerCipher.doFinal(Arrays.copyOf(payload, 1163));
        }

        AlgorithmParameterSpec getAlgoParam(int packetNum) {
            //i dont trust this, but lets use it for now
            BigInteger nonceInt = new BigInteger(secrets.iv).xor(BigInteger.valueOf(packetNum)); // packet num
            return new GCMParameterSpec(128, nonceInt.toByteArray());
        }
    }
}
