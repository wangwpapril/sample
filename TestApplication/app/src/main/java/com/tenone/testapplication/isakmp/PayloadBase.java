package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadBase {
    public byte nextPayload;
    public byte reserved;
    public int payloadLength;
    private int remaining;

    PayloadBase(ByteBuffer buffer) {
        nextPayload = buffer.get();
        reserved = buffer.get();
        payloadLength = buffer.getShort();
        remaining = buffer.remaining();
    }

    PayloadBase(ByteBuffer buffer, int length) {

    }

    protected boolean isValid() {
        return (payloadLength - 4 > 0 && payloadLength - 4 < remaining) ;
    }
}
