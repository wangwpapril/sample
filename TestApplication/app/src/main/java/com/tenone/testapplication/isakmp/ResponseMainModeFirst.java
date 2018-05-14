package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseMainModeFirst extends ResponseBase {

    public ResponseMainModeFirst(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (isakmpHeader != null
                && !isakmpHeader.isEncrypted()
                &&  isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_MAIN_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        int next = isakmpHeader.nextPayload;
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

    @Override
    public boolean isValid() {
        return isakmpHeader != null && payloadList.size() > 0;
    }
}
