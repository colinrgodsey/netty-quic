package com.colingodsey.quic.crypto;

import java.security.Security;

import com.colingodsey.quic.utils.QUICRandom;
import javax.net.ssl.SSLContext;

public class TLS {
    static final SSLContext context;

    static {
        try {
            Security.insertProviderAt(new org.openjsse.net.ssl.OpenJSSE(), 1);

            context = SSLContext.getInstance("TLS");
            context.init(null, null, QUICRandom.getSecureRandom());
            context.createSSLEngine();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TLS context: ", e);
        }
    }

    public static void init() {
        // NOOP
    }

    private TLS() {
        // NOOP
    }
}
