package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public abstract class ResponseCommonBase extends ResponseBase {
    public ResponseCommonBase(ByteBuffer buffer) {
        super(buffer);
        if (isDataValid()) {
            parseData(buffer);
        }
    }

    @Override
    boolean isDataValid() {
        return (isakmpHeader != null
                && !isakmpHeader.isEncrypted());
    }

    @Override
    void parseData(ByteBuffer buffer) {
        while (next > 0) {
            PayloadBase payload = parsePayload(next, buffer);
            if (payload != null) {
                payloadList.add(payload);
                next = payload.nextPayload;
            }else {
                break;
            }
        }

    }

}
