package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;
import java.util.ArrayList;

import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.utils.QUICRandom;

public class VersionNegotiation implements Packet {
    public final LongHeader header;
    public final int[] versions;

    public VersionNegotiation(ByteBuf in) {
        final ArrayList<Integer> versionsArr = new ArrayList<>();
        header = new LongHeader(in);
        while (in.isReadable()) {
            versionsArr.add(in.readInt());
        }
        versions = new int[versionsArr.size()];
        for (int i = 0 ; i < versions.length ; i++) {
            versions[i] = versionsArr.get(i);
        }
    }

    public VersionNegotiation(BigInteger sourceID, BigInteger destID, int[] versions) {
        this.header = new LongHeader(Type.random(), QUICRandom.nextNibble(), 0, sourceID, destID);
        this.versions = versions;
    }

    public void write(ByteBuf out) {
        header.write(out);
        for (int version : versions) {
            out.writeInt(version);
        }
    }
}
