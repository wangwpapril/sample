package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class PayloadAttribute extends PayloadBase {
    public int type;
    public int identifier;
    public byte[] attributes;

    public PayloadAttribute(ByteBuffer buffer) {
        super(buffer);

        if (isValid()) {
            type = buffer.get();
            buffer.get();
            identifier = buffer.getShort();
            attributes = new byte[payloadLength - 8];
            buffer.get(attributes, 0, payloadLength - 8);
        }
    }
}
