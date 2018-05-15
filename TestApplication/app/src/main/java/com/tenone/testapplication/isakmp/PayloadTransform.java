package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadTransform extends PayloadBase{
    public byte number;
    public byte id;
    public byte[] reserved2 = new byte[2];
    public List<DataAttribute> attributeList = new ArrayList<>();

    public PayloadTransform(ByteBuffer buffer) {
        super(buffer);

        if (isValid()) {
            number = buffer.get();
            id = buffer.get();
            buffer.get(reserved2, 0, 2);

            if (this.payloadLength - 8 > 0) {
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
