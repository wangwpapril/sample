package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseMainModeThird extends ResponseBase {
    private byte[] encryptedData;

    public ResponseMainModeThird(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (isakmpHeader != null
                && isakmpHeader.isEncrypted()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_MAIN_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {

        encryptedData = new byte[isakmpHeader.payloadLength - 28];
        buffer.get(encryptedData, 0, isakmpHeader.payloadLength - 28);
        byte[] decryptedData = KeyExchangeUtil.getInstance().decryptData(encryptedData);
        if (decryptedData != null) {
            buffer.clear();
            buffer.put(decryptedData);
            buffer.position(0);
        }else {
            buffer.clear();
            next = 0;
        }

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

    public byte[] getNextIv() {
        byte[] Iv = new byte[16];
        System.arraycopy(encryptedData, encryptedData.length - 16, Iv, 0, 16);
        return Iv;
    }

}