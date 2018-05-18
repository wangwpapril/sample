package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseQuickModeFirst extends ResponseDecryptBase {
    public ResponseQuickModeFirst(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (super.isDataValid()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_QUICK_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        super.parseData(buffer);
        generateHash();
        hashCompare();
    }

    @Override
    boolean prepareIV() {
        return true;
    }

    @Override
    public boolean isValid() {
        return super.isValid() && attributeType == 2;
    }
}
