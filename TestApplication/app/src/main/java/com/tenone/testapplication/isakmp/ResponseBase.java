package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by willwang on 2018-05-03.
 */

abstract public class ResponseBase {
    public IsakmpHeader isakmpHeader;
    public List<PayloadBase> payloadList = new ArrayList<>();
    protected int next;

    public ResponseBase(ByteBuffer buffer) {
        isakmpHeader = new IsakmpHeader(buffer);
        next = isakmpHeader.nextPayload;

        if (isDataValid()) {
            parseData(buffer);
        }
    }

    abstract boolean isDataValid();

    abstract void parseData(ByteBuffer buffer);

    abstract public boolean isValid();

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
            case Constants.ISAKMP_NPTYPE_ATTR:
                PayloadAttribute payloadAttribute = new PayloadAttribute(buffer);
                return payloadAttribute;
            default:
                return null;
        }

    }

}
