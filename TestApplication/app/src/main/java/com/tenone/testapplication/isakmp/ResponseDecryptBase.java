package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.Arrays;

public abstract class ResponseDecryptBase extends ResponseBase {
    protected byte[] encryptedData;
    protected byte[] decryptedData;
    protected byte[] hashGenerated;
    protected byte[] hashData;
    protected int totalLength;
    protected boolean hashMatched;

    protected boolean attributesValid;
    protected int attributeType;
    protected int attributeSize;

    protected boolean hasDeletePayload;

    public ResponseDecryptBase(ByteBuffer buffer) {
        super(buffer, true);
        if (isDataValid() && prepareIV()) {
            decryptData(buffer);

            parseData(buffer);
        }
    }

    @Override
    boolean isDataValid() {
        return (isakmpHeader != null
                && isakmpHeader.isEncrypted());
    }

    @Override
    void parseData(ByteBuffer buffer) {
        while (next > 0) {
            PayloadBase payload = parsePayload(next, buffer);
            if (payload != null) {
                payloadList.add(payload);
                next = payload.nextPayload;
                if (payload instanceof PayloadHash) {
                    hashData = ((PayloadHash) payload).hashData;
                }else {
                    totalLength += payload.payloadLength;
                }

                if (payload instanceof PayloadAttribute) {
                    if (((PayloadAttribute) payload).attributeList != null) {
                        attributesValid = true;
                        attributeSize = ((PayloadAttribute) payload).attributeList.size();
                        attributeType = ((PayloadAttribute) payload).type;

                    }
                }else if (payload instanceof PayloadDelete) {
                    hasDeletePayload = true;
                }

            }else {
                break;
            }
        }

    }

    void decryptData(ByteBuffer buffer) {
        encryptedData = new byte[isakmpHeader.payloadLength - 28];
        buffer.get(encryptedData, 0, isakmpHeader.payloadLength - 28);
        decryptedData = AlgorithmUtil.getInstance().aesDecryptData(KeyExchangeUtil.getInstance().getSKEYIDe(), encryptedData);
        //decryptedData = KeyExchangeUtil.getInstance().decryptData(encryptedData);
        if (decryptedData != null) {
            buffer.clear();
            buffer.put(decryptedData);
            buffer.position(0);
        }else {
            buffer.clear();
            next = 0;
        }

    }

    void generateHash() {
        byte[] data = new byte[totalLength];
        System.arraycopy(decryptedData, 36,
                data, 0, totalLength);

        hashGenerated = PayloadHelper.getInstance().generateHashDataForPayload(
                Utils.toBytes(isakmpHeader.messageId, 4),
                data
        );

    }

    abstract boolean prepareIV();

    public byte[] getNextIv() {
        if (encryptedData != null && encryptedData.length > 16) {
            byte[] Iv = new byte[16];
            System.arraycopy(encryptedData, encryptedData.length - 16, Iv, 0, 16);
            return Iv;
        }else {
            return null;
        }
    }

    protected void hashCompare() {
        if (hashGenerated != null && hashData != null
                && hashGenerated.length == hashData.length) {
            hashMatched = Arrays.equals(hashGenerated, hashData);
        }
    }

    @Override
    public boolean isValid() {
        return payloadList.size() > 0 && hashMatched;
    }

}
