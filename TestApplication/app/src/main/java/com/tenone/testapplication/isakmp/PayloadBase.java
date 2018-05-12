package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadBase {
    public byte nextPayload;
    public byte reserved;
    public int payloadLength;

    PayloadBase(ByteBuffer buffer) {
        nextPayload = buffer.get();
        reserved = buffer.get();
        payloadLength = buffer.getShort();

    }

    PayloadBase(ByteBuffer buffer, int length) {

    }
}
