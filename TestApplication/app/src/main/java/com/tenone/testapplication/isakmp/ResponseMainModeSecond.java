package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseMainModeSecond extends ResponseCommonBase {

    public ResponseMainModeSecond(ByteBuffer buffer) {
        super(buffer);

    }

    @Override
    boolean isDataValid() {
        return (super.isDataValid()
                &&  isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_MAIN_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        super.parseData(buffer);
    }

    @Override
    public boolean isValid() {
        return isakmpHeader != null && payloadList.size() > 0;
    }
}
