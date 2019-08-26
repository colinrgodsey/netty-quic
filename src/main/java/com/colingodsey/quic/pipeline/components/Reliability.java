package com.colingodsey.quic.pipeline.components;

import com.colingodsey.quic.packet.Packet;

/*
ideas:
Send each frame with a promise. Fail the promise on revocation, then resend.

Needs: Packet reliability layer and Stream resend layer.

Frame producers (and frameordering) just need to resend on failure.
 */
public class Reliability<T extends Packet> {
    long packetNumber = 0;
}
