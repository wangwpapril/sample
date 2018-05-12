package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by willwang on 2018-05-03.
 */

public class ResponseBase {
    public IsakmpHeader isakmpHeader;
    public List<PayloadBase> payloadList = new ArrayList<>();
    public boolean encrypted;

    public ResponseBase(ByteBuffer buffer) {
        isakmpHeader = new IsakmpHeader(buffer);
        if (isakmpHeader != null) {
            int next = isakmpHeader.nextPayload;
            encrypted = isakmpHeader.isEncrypted();

            if (encrypted) {
                byte[] encryptedData = new byte[isakmpHeader.payloadLength - 28];
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
    }

    public IsakmpHeader getResHeader() {
        return isakmpHeader;
    }

    public static PayloadBase parsePayload(int type, ByteBuffer buffer) {
        switch (type) {
            case Constants.ISAKMP_NPTYPE_SA:
                PayloadSA payloadSA = new PayloadSA(buffer);
                return payloadSA;
            case Constants.ISAKMP_NPTYPE_VID:
                PayloadVendorID payloadVendorID = new PayloadVendorID(buffer);
                return payloadVendorID;
            case Constants.ISAKMP_NPTYPE_HASH:
                PayloadHash payloadHash = new PayloadHash(buffer);
                return payloadHash;
            case Constants.ISAKMP_NPTYPE_NONCE:
                PayloadNonce payloadNonce = new PayloadNonce(buffer);
                return payloadNonce;
            case Constants.ISAKMP_NPTYPE_KE:
                PayloadKeyEx payloadKeyEx = new PayloadKeyEx(buffer);
                return payloadKeyEx;
            case Constants.ISAKMP_NPTYPE_T:
                PayloadTransform payloadTransform = new PayloadTransform(buffer);
                return payloadTransform;
            case Constants.ISAKMP_NPTYPE_NAT_D:
                PayloadNatD payloadNatD = new PayloadNatD(buffer);
                return payloadNatD;
            case Constants.ISAKMP_NPTYPE_ID:
                PayloadIdentification payloadIdentification = new PayloadIdentification(buffer);
                return payloadIdentification;
            default:
                return null;
        }

    }

}
