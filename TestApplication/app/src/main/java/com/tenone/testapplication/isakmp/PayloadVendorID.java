package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadVendorID extends PayloadBase {
    public byte[] vendorId;

    public PayloadVendorID(ByteBuffer buffer) {
        super(buffer);
        if (isValid()) {
            vendorId = new byte[payloadLength - 4];
            buffer.get(vendorId, 0, payloadLength - 4);
        }
    }
}
