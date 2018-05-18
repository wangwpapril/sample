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
    void generateHash() {
        byte[] nibody = KeyExchangeUtil.getInstance().getNonce(2).toByteArray();
        byte[] data = new byte[totalLength + nibody.length];
        System.arraycopy(nibody, 0, data, 0, nibody.length);
        System.arraycopy(decryptedData, 36,
                data, nibody.length, totalLength);

        hashGenerated = KeyExchangeUtil.getInstance().generateHashDataForAttributePayload(
                Utils.toBytes(isakmpHeader.messageId, 4),
                data
        );

    }

    @Override
    boolean prepareIV() {
        return true;
    }

    @Override
    public boolean isValid() {
        return super.isValid();
    }
}
