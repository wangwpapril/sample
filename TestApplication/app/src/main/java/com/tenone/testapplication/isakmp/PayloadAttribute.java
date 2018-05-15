package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class PayloadAttribute extends PayloadBase {
    public int type;
    public int identifier;
    public byte[] attributes;
    public List<DataAttribute> attributeList = new ArrayList<>();

    public PayloadAttribute(ByteBuffer buffer) {
        super(buffer);

        if (isValid()) {
            type = buffer.get();
            buffer.get();
            identifier = buffer.getShort();

            if (this.payloadLength - 8 > 0) {
                attributes = new byte[payloadLength - 8];
                buffer.get(attributes, 0, payloadLength - 8);
                int attSize = this.payloadLength - 8;
                while (attSize > 0) {
                    DataAttribute dataAttribute = new DataAttribute(buffer);
                    if (dataAttribute != null) {
                        attributeList.add(dataAttribute);
                        attSize -= dataAttribute.totalLength;
                    } else {
                        break;
                    }
                }
            }

        }
    }
}
