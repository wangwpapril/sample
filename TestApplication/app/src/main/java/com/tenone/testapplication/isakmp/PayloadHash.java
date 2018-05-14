package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-04.
 */

public class PayloadHash extends PayloadBase {
    public byte[] hashData;

    public PayloadHash(ByteBuffer buffer) {
        super(buffer);
        if (payloadLength - 4 > 0 && payloadLength <= buffer.remaining()) {
            hashData = new byte[payloadLength - 4];
            buffer.get(hashData, 0, payloadLength - 4);
        }
    }
}
