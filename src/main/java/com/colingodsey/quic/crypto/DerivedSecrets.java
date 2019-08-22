package com.colingodsey.quic.crypto;

import static com.colingodsey.quic.utils.Utils.h2ba;

import at.favre.lib.crypto.HKDF;

import com.colingodsey.quic.packet.components.ConnectionID;

public class DerivedSecrets {
    static final byte[] quicV1InitialSalt = h2ba("c3eef712c72ebb5a11a7d2432bb46365bef9f502");
    static final byte[] clientInBytes = h2ba("00200f746c73313320636c69656e7420696e00"); //"client in"
    static final byte[] serverInBytes = h2ba("00200f746c7331332073657276657220696e00"); //"server in"
    static final byte[] keyBytes = h2ba("00100e746c7331332071756963206b657900"); //"quic key"
    static final byte[] ivBytes = h2ba("000c0d746c733133207175696320697600"); //"quic iv"
    static final byte[] hpBytes = h2ba("00100d746c733133207175696320687000"); //"quic hp"
    static final int HASH_BYTES = 32;

    static final HKDF hkdf = HKDF.fromHmacSha256();

    public final byte[] initialSecret;
    public final byte[] clientInitialSecret;
    public final byte[] serverInitialSecret;
    public final PacketSecrets clientSecrets;
    public final PacketSecrets serverSecrets;

    public DerivedSecrets(ConnectionID conID) {
        initialSecret = hkdf.extract(quicV1InitialSalt, conID.getBytes());
        clientInitialSecret = hkdf.expand(initialSecret, clientInBytes, HASH_BYTES);
        serverInitialSecret = hkdf.expand(initialSecret, serverInBytes, HASH_BYTES);
        clientSecrets = new PacketSecrets(clientInitialSecret);
        serverSecrets = new PacketSecrets(serverInitialSecret);
    }

    public class PacketSecrets {
        public final byte[] key;
        public final byte[] iv;
        public final byte[] hp;

        PacketSecrets(byte[] secret) {
            key = hkdf.expand(secret, keyBytes, 16);
            iv = hkdf.expand(secret, ivBytes, 12);
            hp = hkdf.expand(secret, hpBytes, 16);
        }
    }
}
