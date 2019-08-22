package com.colingodsey.quic.crypto.context;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public abstract class Context {
    abstract public IKeyStack getClient();
    abstract public IKeyStack getServer();

    abstract public class IKeyStack {
        abstract public byte[] encryptPayload(byte[] header, byte[] payload, int packetNumber)
                throws InvalidAlgorithmParameterException, InvalidKeyException,
                BadPaddingException, IllegalBlockSizeException;
    }
}
