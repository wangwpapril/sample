package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-04.
 */

public class PayloadKeyEx extends PayloadBase {
    public byte[] keyExData;

    public PayloadKeyEx(ByteBuffer buffer) {
        super(buffer);
        if (isValid()) {
            keyExData = new byte[payloadLength - 4];
            buffer.get(keyExData, 0, payloadLength - 4);
        }
    }
}
