package com.tenone.testapplication.isakmp;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The class contains method for handling payload request and response
 */

public class PayloadHelper {

    private static final int GENERIC_HEADER_LENGTH = 28;
    private static final int NON_ESP_MARKER_LENGTH = 4;

    private static final int IKE_ATTRIBUTE_1 = 1;   // encryption-algorithm
    private static final int IKE_ATTRIBUTE_2 = 2;   // hash-algorithm
    private static final int IKE_ATTRIBUTE_3 = 3;   // authentication-method
    private static final int IKE_ATTRIBUTE_4 = 4;   // group-description
    private static final int IKE_ATTRIBUTE_11 = 11; // life-type
    private static final int IKE_ATTRIBUTE_12 = 12; // life-duration
    private static final int IKE_ATTRIBUTE_14 = 14; // key-length
    private static final String TAG = "PayloadHelper";

    private static PayloadHelper instance;
    private KeyExchangeUtil mKeyExchangeUtil;
    private AlgorithmUtil mAlgorithmUtil;
    private IsakmpHeader isakmpHeader;
    private String mPresharedSecret;
    private String mLocalAddress;
    private String mServerAddress;
    private String mISAKMPPort;
    private String mUserName;
    private String mPassword;
    private int mESPSequenceNumber;
    private byte[] mPhase1SAPayload;
    private byte[] mServerProvidedIpAddress;
    private byte[] mServerProvidedSubnet;

    public static PayloadHelper getInstance() {
        if (instance == null) {
            instance = new PayloadHelper();
        }

        return instance;
    }

    private PayloadHelper() {
        mKeyExchangeUtil = KeyExchangeUtil.getInstance();
        mAlgorithmUtil = AlgorithmUtil.getInstance();
    }

    public void init(String presharedSecret, String localAddress, String serverAddress, String port,
                     String userName, String password) {
        mPresharedSecret = presharedSecret;
        mLocalAddress = localAddress;
        mServerAddress = serverAddress;
        mISAKMPPort = port;
        mUserName = userName;
        mPassword = password;
    }

    public byte[] getPhase1SAPayload() {
        return mPhase1SAPayload;
    }

    public void setIsakmpHeader(IsakmpHeader header) {
        isakmpHeader = header;
    }

    /**
     * Prepare the generic header which is 28 bytes long. RFC2048.
     * @param nextPayloadType
     * @return
     */
    public byte[] prepareHeader(int nextPayloadType) {
        byte[] nextPayload = Utils.toBytes(nextPayloadType, 1);    // Security Association
        byte[] version = new byte[1];
        version[0] |= 1 << 4;       // Major version: 1 (first 4 bits), Minor version: 0 (last 4 bits)
        byte[] exchangeType = Utils.toBytes(2, 1);  // 2 - Identity Protection (Main mode)
        byte[] flags = new byte[1];
        byte[] messageId = new byte[4];
        byte[] payloadLength = new byte[4];

        byte[][] dataArray = {mKeyExchangeUtil.getInitiatorCookie(),
                mKeyExchangeUtil.getResponderCookie(), nextPayload, version, exchangeType, flags, messageId, payloadLength};

        byte[] header = Utils.combineData(dataArray);

        return header;
    }

    /**
     * Prepare the first sending message of main mode in phase 1
     * @return
     */
    public byte[] preparePhase1MainModeFirstMsg() {

        mKeyExchangeUtil.initialize(mLocalAddress, mServerAddress);

        byte[] header = prepareHeader(1/*SA Payload*/);
        mPhase1SAPayload = prepareSAPayload();

        byte[] vidPayloads = prepareVendorIDPayloads();

        int size = header.length + mPhase1SAPayload.length + vidPayloads.length;
        byte[] payloadLength = Utils.toBytes(size);

        byte[][] dataArray = {Arrays.copyOfRange(header, 0, 24), payloadLength, mPhase1SAPayload, vidPayloads};
        return Utils.combineData(dataArray);
    }

    /**
     * Prepare the second message of main mode in phase 1
     * @return
     */
    public byte[] preparePhase1MainModeSecondMsg() {

        byte[] keyExchangePayload = prepareKeyExchangePayload();
        byte[] noncePayload = prepareNoncePayload(20, 1);
        byte[] natPayload1 = prepareNatPayload(20, mServerAddress);
        byte[] natPayload2 = prepareNatPayload(0, mLocalAddress);
        byte[] header = isakmpHeader.toData(4);
        int size = header.length + keyExchangePayload.length + noncePayload.length + natPayload1.length + natPayload2.length;
        byte[] headerWithUpdatedLength = new byte[header.length];
        System.arraycopy(header, 0, headerWithUpdatedLength, 0, 24);
        System.arraycopy(Utils.toBytes(size), 0, headerWithUpdatedLength, 24, 4);

        byte[][] dataArray = {headerWithUpdatedLength, keyExchangePayload, noncePayload, natPayload1, natPayload2};
        return Utils.combineData(dataArray);
    }

    /**
     * Prepare the third message of main mode in phase 1
     * @return
     */
    public byte[] preparePhase1MainModeThirdMsg() {

        byte[] flag = Utils.toBytes(1, 1);
        if (mKeyExchangeUtil.instantiateServerPublicKey()) {
            mKeyExchangeUtil.generateExchangeInfo();

            byte[] idPayload = prepareIdentificationPayload();
            byte[] hashPayload = prepareHashPayloadForIDPayload(idPayload);
            byte[][] dataArray1 = {idPayload, hashPayload};
            byte[] combineData = Utils.combineData(dataArray1);

            byte[] encryptedData = prepareMainMode1stEncryptedPayload(combineData);
            byte[] header = isakmpHeader.toData(5, encryptedData.length + GENERIC_HEADER_LENGTH, flag[0]);

            byte[][] dataArray2 = {getNonESPMarker(), header, encryptedData};
            byte[] msg = Utils.combineData(dataArray2);

            updateIVWithEncryptedData(encryptedData);

            return msg;
        }

        return null;
    }

    /**
     * Prepare the first message of config mode in phase 2
     * @return
     */
    public byte[] preparePhase2ConfigModeFirstMsg() {
        byte[] loginConfigPayload = prepareLoginConfigPayload(Utils.toBytes(isakmpHeader.messageId));
        byte[] header = isakmpHeader.toData(8, GENERIC_HEADER_LENGTH + loginConfigPayload.length, isakmpHeader.flags);

        byte[][] dataArray ={getNonESPMarker(), header, loginConfigPayload};
        return Utils.combineData(dataArray);
    }

    /**
     * Prepare the second message of config mode in phase 2
     * @return
     */
    public byte[] preparePhase2ConfigModeSecondMsg() {

        byte[] ackConfigPayload = prepareAcknowledgeConfigPayload(Utils.toBytes(isakmpHeader.messageId));
        byte[] header = isakmpHeader.toData(8/*Acknowledge config payload*/,
                GENERIC_HEADER_LENGTH + ackConfigPayload.length, isakmpHeader.flags);

        byte[][] dataArray = {getNonESPMarker(), header, ackConfigPayload};
        byte[] msg = Utils.combineData(dataArray);

        print("preparePhase2ConfigModeSecondMsg", msg);

        return msg;
    }

    /**
     * Prepare the third message of config mode in phase 2
     * @return
     */
    public byte[] preparePhase2ConfigModeThirdMsg() {

        SecureRandom random = new SecureRandom();
        int messageId = random.nextInt();
        byte[] messageIdBytes = Utils.toBytes(messageId);
        preparePhase2IV(messageIdBytes);
        byte[] ipConfigPayload = prepareIpConfigPayload(messageIdBytes);

        byte[] header = isakmpHeader.toData(8, messageId);
        byte[][] dataArray = {getNonESPMarker(), Arrays.copyOfRange(header, 0, 24),
                Utils.toBytes(GENERIC_HEADER_LENGTH + ipConfigPayload.length), ipConfigPayload};
        byte[] msg = Utils.combineData(dataArray);

        print("preparePhase2ConfigModeThirdMsg", msg);

        return msg;
    }

    /**
     * Prepare the first message of quick mode in phase 2
     * @return
     */
    public byte[] preparePhase2QuickModeFirstMsg() {

        mESPSequenceNumber = 0;

        SecureRandom random = new SecureRandom();
        int messageId = random.nextInt();
        byte[] messageIdBytes = Utils.toBytes(messageId);

        print("Quick mode 1st message id. ", messageIdBytes);
        // use the last 16 bytes from last encrypted message in phase 1 + current message id
        preparePhase2IV(messageIdBytes);

        byte[] saPayload = preparePhase2SAPayload();
        print("saPayload 1st message in quick mode. ", saPayload);

        byte[] noncePayload = prepareNoncePayload(5, 2);
        print("noncePayload 1st message in quick mode. ", noncePayload);

        byte[] idPayload1 = preparePhase2IDPayload1(mServerProvidedIpAddress);
        print("idPayload1 1st message in quick mode. ", idPayload1);

        byte[] idPayload2 = preparePhase2IDPayload2(mServerProvidedSubnet);
        print("idPayload2 1st message in quick mode. ", idPayload2);

        byte[][] allPayloads = new byte[4][];
        allPayloads[0] = saPayload;
        allPayloads[1] = noncePayload;
        allPayloads[2] = idPayload1;
        allPayloads[3] = idPayload2;

        byte[] hashData = generateHashDataForPayloads(messageIdBytes, allPayloads);
        print("hashData 1st message in quick mode. ", hashData);

        byte[] hashPayload = prepareHashPayload(hashData, 1);

        byte[][] dataArray1 = {hashPayload, saPayload, noncePayload, idPayload1, idPayload2};
        byte[] dataForEncryption = Utils.combineData(dataArray1);

        byte[] encryptedData = AlgorithmUtil.getInstance().aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), dataForEncryption);
        int len = GENERIC_HEADER_LENGTH + encryptedData.length;
        isakmpHeader.updatePayloadLength(len);
        byte[] header = isakmpHeader.toData(8, messageId, 32);

        byte[][] dataArray2 = {getNonESPMarker(), header, encryptedData};
        byte[] msg = Utils.combineData(dataArray2);

        print("1st message in quick mode. ", msg);

        return msg;
    }

    /**
     * Prepare the second message of quick mode in phase 2
     * @return
     */
    public byte[] preparePhase2QuickModeSecondMsg() {
        byte[] zero = new byte[1];
        byte[] nonce = mKeyExchangeUtil.getNonce(2).toByteArray();
        byte[] messageIdBytes = Utils.toBytes(isakmpHeader.messageId);

        byte[][] dataArray1 = {zero, messageIdBytes, nonce, mKeyExchangeUtil.getResponderNonce(2)};
        byte[] dataForHash = Utils.combineData(dataArray1);

        byte[] hashData = hashPhase2Payload(dataForHash);

        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        int hashPayloadLen = nextPayload.length + reserved.length + 2 + hashData.length;
        byte[] hashPayloadLength = Utils.toBytes(hashPayloadLen, 2);
        byte[][] dataArray2 = {nextPayload, reserved, hashPayloadLength, hashData};
        byte[] hashPayload = Utils.combineData(dataArray2);

        byte[] encryptedData = AlgorithmUtil.getInstance().aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), hashPayload);
        int totalLen = GENERIC_HEADER_LENGTH + encryptedData.length;
        isakmpHeader.updatePayloadLength(totalLen);
        byte[] header = isakmpHeader.toData(8);

        byte[][] dataArray3 = {getNonESPMarker(), header, encryptedData};
        byte[] msg = Utils.combineData(dataArray3);

        return msg;
    }

    /**
     * Prepare ESP payload after tunnel established successfully
     * @param inputData
     * @return
     */
    public byte[] prepareESPPayload(byte[] inputData) {

        byte[] newIv = genereateRandomBytes(AlgorithmUtil.AES_BLOCK_SIZE);
        mAlgorithmUtil.setIv(newIv);

        int len = inputData.length + 1/*padLength*/ + 1/*nextHeader*/;

        int padLength = len % AlgorithmUtil.AES_BLOCK_SIZE;
        if (padLength != 0) {
            padLength = AlgorithmUtil.AES_BLOCK_SIZE - padLength;
            len += padLength;
        }

        byte[] padBytes = null;
        if (padLength > 0) {
            padBytes = new byte[padLength];
        }
        byte[] nextHeader = Utils.toBytes(4, 1);
        byte[][] dataArray1 = {inputData, padBytes, Utils.toBytes(padLength, 1), nextHeader};
        byte[] dataForEncryption = Utils.combineData(dataArray1);
        print("ESP payload before adding header and encrypted. PadLength: " + padLength, dataForEncryption);

        byte[] encryptedData = mAlgorithmUtil.aesEncryptData(mKeyExchangeUtil.getOutboundEncryptionKey(), dataForEncryption, false);
        byte[] outboundSPI = mKeyExchangeUtil.getOutboundSPI();

        len = outboundSPI.length + 4/*mESPSequenceNumber*/ + newIv.length + encryptedData.length;

        byte[][] dataArray2 = {outboundSPI, Utils.toBytes(++mESPSequenceNumber), newIv, encryptedData};
        byte[] payload = Utils.combineData(dataArray2);

        // append the first 12 bytes of Integrity Check Value (ICV) for authentication check. RFC4303
        byte[] fullICVBytes = mAlgorithmUtil.hashDataWithKey(mKeyExchangeUtil.getOutboundAuthenticationKey(), payload);
        byte[] payloadWithICV = new byte[payload.length + 12];
        System.arraycopy(payload, 0, payloadWithICV, 0, payload.length);
        // only copy the first 12 bytes
        System.arraycopy(fullICVBytes, 0, payloadWithICV, payload.length, 12);

//        print("****** ESP Payload", payloadWithICV);

        return payloadWithICV;
    }

    public byte[] getServerProvidedIp() {
        return mServerProvidedIpAddress;
    }

    public byte[] getServerProvidedSubnet() {
        return mServerProvidedSubnet;
    }

    public void setServerProvidedIpAndSubnet(byte[] serverProvidedIpAddress, byte[] serverProvidedSubnet) {
        mServerProvidedIpAddress = serverProvidedIpAddress;
        mServerProvidedSubnet = serverProvidedSubnet;
    }

    public byte[] generateHashDataForMainModeMessage(byte[] responderIDPayload) {
        byte[] initiatorPublicKey = mKeyExchangeUtil.getPublicKey();
        byte[] serverPublicKey = mKeyExchangeUtil.getServerPublicKeyData();
        byte[] initiatorCookie = mKeyExchangeUtil.getInitiatorCookie();
        byte[] responderCookie = mKeyExchangeUtil.getResponderCookie();

        byte[][] dataArray = {serverPublicKey, initiatorPublicKey, responderCookie, initiatorCookie,
                Arrays.copyOfRange(mPhase1SAPayload, 4, mPhase1SAPayload.length), responderIDPayload};
        byte[] data = Utils.combineData(dataArray);

        byte[] hashData = mAlgorithmUtil.hashDataWithKey(mKeyExchangeUtil.getSKEYID(), data);

//        print("Responder's 1st responderIDPayload", responderIDPayload);
//        print("Responder's 1st HashData", hashData);

        return hashData;
    }

    /**
     * Update the Initialization Vector (IV) using the last block of the encrypted data. RFC2409.
     * @param encryptedData
     */
    public void updateIVWithEncryptedData(byte[] encryptedData) {
        byte[] Iv = new byte[AlgorithmUtil.AES_BLOCK_SIZE];
        System.arraycopy(encryptedData, encryptedData.length - AlgorithmUtil.AES_BLOCK_SIZE,
                Iv, 0, AlgorithmUtil.AES_BLOCK_SIZE);
        mAlgorithmUtil.setIv(Iv);
    }

    /**
     * Prepare the phase 1 SA payload
     * @return
     */
    private byte[] prepareSAPayload() {

        byte[] nextPayload = Utils.toBytes(13/*Vendor payload*/, 1);
        //nextPayload[0] = 0;
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] doi = Utils.toBytes(1);
        byte[] situation = Utils.toBytes(1);

        byte[] proposalPayload = prepareProposalPayload();

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + doi.length + situation.length + proposalPayload.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, doi, situation, proposalPayload};
        byte[] saPayload = Utils.combineData(dataArray);

        return saPayload;

    }

    /**
     * Proposal payload. Currently has only one transform payload which uses AES_CBC for encryption, and SHA2-256 for hash
     * @return
     */
    private byte[] prepareProposalPayload1() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(1, 1);
        byte[] spiSize = new byte[1];
        byte[] transformNumber = Utils.toBytes(1, 1);

        byte[] transformPayload1 = prepareTransformPayload(1, true);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + transformPayload1.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, proposalNumber, protocolId, spiSize, transformNumber, transformPayload1};
        byte[] proposalPayload = Utils.combineData(dataArray);

        return proposalPayload;
    }

    /**
     * Not using at this time. Propose 15 transforms that we support
     * @return
     */
    private byte[] prepareProposalPayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(1, 1);
        byte[] spiSize = new byte[1];
        byte[] transformNumber = Utils.toBytes(15, 1);

        byte[] transformPayload1 = prepareTransformPayload(1);
        byte[] transformPayload2 = prepareTransformPayload(2);
        byte[] transformPayload3 = prepareTransformPayload(3);
        byte[] transformPayload4 = prepareTransformPayload(4);
        byte[] transformPayload5 = prepareTransformPayload(5);
        byte[] transformPayload6 = prepareTransformPayload(6);
        byte[] transformPayload7 = prepareTransformPayload(7);
        byte[] transformPayload8 = prepareTransformPayload(8);
        byte[] transformPayload9 = prepareTransformPayload(9);
        byte[] transformPayload10 = prepareTransformPayload(10);
        byte[] transformPayload11 = prepareTransformPayload(11);
        byte[] transformPayload12 = prepareTransformPayload(12);
        byte[] transformPayload13 = prepareTransformPayload(13);
        byte[] transformPayload14 = prepareTransformPayload(14);
        byte[] transformPayload15 = prepareTransformPayload(15, true);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + transformPayload1.length +
                transformPayload2.length + transformPayload3.length + transformPayload4.length +
                transformPayload5.length + transformPayload6.length + transformPayload7.length +
                transformPayload8.length + transformPayload9.length + transformPayload10.length +
                transformPayload11.length + transformPayload12.length + transformPayload13.length +
                transformPayload14.length + transformPayload15.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, proposalNumber, protocolId, spiSize, transformNumber,
                transformPayload1, transformPayload2, transformPayload3, transformPayload4, transformPayload5, transformPayload6,
                transformPayload7, transformPayload8, transformPayload9, transformPayload10, transformPayload11, transformPayload12,
                transformPayload13, transformPayload14, transformPayload15};

        byte[] proposalPayload = Utils.combineData(dataArray);

        return proposalPayload;
    }

    /**
     * Prepare teh transform payload
     * @param i
     * @return
     */
    private byte[] prepareTransformPayload(int i) {
        return prepareTransformPayload(i, false);
    }

    private byte[] prepareTransformPayload(int i, boolean lastOne) {
        byte[] nextPayload = null;
        if (!lastOne) {
            nextPayload = Utils.toBytes(3, 1);  // 3 - Transform payload
        } else {
            nextPayload = Utils.toBytes(0, 1);  // 0 - none (no more)
        }
        //nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] transformNumber = Utils.toBytes(i, 1);
        byte[] transformId = Utils.toBytes(1, 1);
        byte[] reserved2 = new byte[2];

        byte[] attributes = prepareIKEAttribute1(i);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + transformNumber.length +
                transformId.length + reserved2.length + attributes.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, transformNumber, transformId, reserved2, attributes};
        byte[] transformPayload = Utils.combineData(dataArray);

        return transformPayload;
    }

    private byte[] prepareIKEAttribute1(int transformNumber) {
        byte[] attr = null;
        switch (transformNumber) {
            case 1:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 4), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 2:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 3:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 4:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 5:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 4), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 6:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 7:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 8:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 9:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 10:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 128), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 11:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 128), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 12:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 5), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 13:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 5), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 14:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 1), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 15:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 1), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            default:
                return null;
        }
    }

    private byte[] prepareIKEAttribute2(int type, int value) {
        byte[] attributeType = new byte[2];
        byte[] attribute2ndPart = null;

        switch (type) {

            case IKE_ATTRIBUTE_1:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 1 - encryption-algorithm
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_2:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 1;     // 2 - hash-algorithm
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_3:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 3 - authentication-method
                attributeType[1] |= 1 << 1;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_4:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 2;     // 4 - group-description
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_11:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 11 - life-type
                attributeType[1] |= 1 << 1;
                attributeType[1] |= 1 << 3;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_12:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 3;     // 12 - life-duration
                attributeType[1] |= 1 << 2;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_14:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 3;     // 14 - key-length
                attributeType[1] |= 1 << 2;
                attributeType[1] |= 1 << 1;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            default:
                break;
        }

        byte[] ikeAttr = new byte[4];
        System.arraycopy(attributeType, 0, ikeAttr, 0, 2);
        System.arraycopy(attribute2ndPart, 0, ikeAttr, 2, 2);

        return ikeAttr;
    }

    private byte[] prepareVendorIDPayloads() {
        byte[] vid_payload1 = prepareVendorPayload(1);
        byte[] vid_payload2 = prepareVendorPayload(2);
        byte[] vid_payload3 = prepareVendorPayload(3);
        byte[] vid_payload4 = prepareVendorPayload(4);
        byte[] vid_payload5 = prepareVendorPayload(5);
        byte[] vid_payload6 = prepareVendorPayload(6);
        byte[] vid_payload7 = prepareVendorPayload(7);
        byte[] vid_payload8 = prepareVendorPayload(8);

        byte[][] dataArray = {vid_payload1, vid_payload2, vid_payload3, vid_payload4, vid_payload5, vid_payload6,
                vid_payload7, vid_payload8};
        byte[] allVidPayloads = Utils.combineData(dataArray);

        return allVidPayloads;
    }

    private byte[] prepareVendorPayload(int num) {
        byte[] nextPayload = null;
        if (num < 8) {
            nextPayload = Utils.toBytes(13, 1);
        } else {
            nextPayload = new byte[1];
        }
        byte[] reserved = new byte[1];
        //byte[] payloadLengtgh = new byte[2];
        byte[] VID_NAT_3947 = {(byte)0x4a, (byte)0x13, (byte)0x1c, (byte)0x81, (byte)0x07, (byte)0x03, (byte)0x58, (byte)0x45, (byte)0x5c, (byte)0x57, (byte)0x28, (byte)0xf2, (byte)0x0e, (byte)0x95, (byte)0x45, (byte)0x2f};
        byte[] VID_IKE2 = {(byte)0xcd, (byte)0x60, (byte)0x46, (byte)0x43, (byte)0x35, (byte)0xdf, (byte)0x21, (byte)0xf8, (byte)0x7c, (byte)0xfd, (byte)0xb2, (byte)0xfc, (byte)0x68, (byte)0xb6, (byte)0xa4, (byte)0x48};
        byte[] VID_IKE2b = {(byte)0x90, (byte)0xcb, (byte)0x80, (byte)0x91, (byte)0x3e, (byte)0xbb, (byte)0x69, (byte)0x6e, (byte)0x08, (byte)0x63, (byte)0x81, (byte)0xb5, (byte)0xec, (byte)0x42, (byte)0x7b, (byte)0x1f};
        byte[] VID_IKE = {(byte)0x44, (byte)0x85, (byte)0x15, (byte)0x2d, (byte)0x18, (byte)0xb6, (byte)0xbb, (byte)0xcd, (byte)0x0b, (byte)0xe8, (byte)0xa8, (byte)0x46, (byte)0x95, (byte)0x79, (byte)0xdd, (byte)0xcc};
        byte[] VID_XAUTH = {(byte)0x09, (byte)0x00, (byte)0x26, (byte)0x89, (byte)0xdf, (byte)0xd6, (byte)0xb7, (byte)0x12};
        byte[] VID_CISCO_UNITY = {(byte)0x12, (byte)0xf5, (byte)0xf2, (byte)0x8c, (byte)0x45, (byte)0x71, (byte)0x68, (byte)0xa9, (byte)0x70, (byte)0x2d, (byte)0x9f, (byte)0xe2, (byte)0x74, (byte)0xcc, (byte)0x01, (byte)0x00};
        byte[] VID_CISCO_FRAGMENT = {(byte)0x40, (byte)0x48, (byte)0xb7, (byte)0xd5, (byte)0x6e, (byte)0xbc, (byte)0xe8, (byte)0x85, (byte)0x25, (byte)0xe7, (byte)0xde, (byte)0x7f, (byte)0x00, (byte)0xd6, (byte)0xc2, (byte)0xd3, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00};
        byte[] VID_NAT_3706 = {(byte)0xaf, (byte)0xca, (byte)0xd7, (byte)0x13, (byte)0x68, (byte)0xa1, (byte)0xf1, (byte)0xc9, (byte)0x6b, (byte)0x86, (byte)0x96, (byte)0xfc, (byte)0x77, (byte)0x57, (byte)0x01, (byte)0x00};
        byte[] data = null;

        switch (num) {
            case 1:
                data = VID_NAT_3947;
                break;

            case 2:
                data = VID_IKE2;
                break;

            case 3:
                data = VID_IKE2b;
                break;

            case 4:
                data = VID_IKE;
                break;

            case 5:
                data = VID_XAUTH;
                break;

            case 6:
                data = VID_CISCO_UNITY;
                break;

            case 7:
                data = VID_CISCO_FRAGMENT;
                break;

            case 8:
                data = VID_NAT_3706;
                break;

            default:
                break;

        }

        int len = nextPayload.length + reserved.length + 2/*payloadLengtgh*/ + data.length;
        byte[] payloadLength = Utils.toBytes(len, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, data};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareKeyExchangePayload() {
        byte[] nextPayload = Utils.toBytes(10/*Nonce payload*/, 1);
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] keyExchangeData = prepareKeyExchangeData();

        int size = nextPayload.length + reserve.length + 2/*payloadLength.length*/ + keyExchangeData.length;
        byte[] payloadLength = Utils.toBytes(size, 2);
        byte[][] dataArray = {nextPayload, reserve, payloadLength, keyExchangeData};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareKeyExchangeData() {
        mKeyExchangeUtil.generatePairKeys(mPresharedSecret);
        return mKeyExchangeUtil.getPublicKey();
    }

    private byte[] prepareNoncePayload(int nextPayloadNumber, int phaseNumber) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNumber, 1);
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] nonce = mKeyExchangeUtil.getNonce(phaseNumber).toByteArray();

        int size = nextPayload.length + reserve.length + 2/*payloadLength.length*/ + nonce.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserve, payloadLength, nonce};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareNatPayload(int nextPayloadNumber, String ipAddress) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNumber, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];

        byte[] ipBytes = Utils.ipv4AddressToBytes(ipAddress);
        byte[] portBytes = Utils.toBytes(Integer.valueOf(mISAKMPPort), 2);

        byte[][] dataArray1 = {isakmpHeader.initiatorCookie, isakmpHeader.responderCookie, ipBytes, portBytes};
        byte[] dataForHash = Utils.combineData(dataArray1);

        byte[] hashData = mAlgorithmUtil.hashData(dataForHash);
        int len = nextPayload.length + reserved.length + 2/*payloadLength*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(len, 2);

        byte[][] dataArray2 = {nextPayload, reserved, payloadLength, hashData};
        byte[] payload = Utils.combineData(dataArray2);

        return payload;
    }

    private byte[] prepareIdentificationPayload() {
        byte[] nextPayload = Utils.toBytes(8, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] idType = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(17, 1);
        byte[] port = Utils.toBytes(Integer.valueOf(mISAKMPPort), 2);

        byte[] data = Utils.ipv4AddressToBytes(mLocalAddress);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + idType.length +
                protocolId.length + port.length + data.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, idType, protocolId, port, data};

        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareHashPayloadForIDPayload(byte[] idPayload) {
        byte[] nextPayload = Utils.toBytes(0, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] hashData = prepareHashPayloadData(idPayload);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, hashData};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareHashPayloadData(byte[] idPayload) {
        // remove the first 4 bytes payload header
        byte[] saPayloadBody = Arrays.copyOfRange(mPhase1SAPayload, 4, mPhase1SAPayload.length);
        byte[] idPayloadBody = Arrays.copyOfRange(idPayload, 4, idPayload.length);

        byte[][] dataArray = {mKeyExchangeUtil.getPublicKey(), mKeyExchangeUtil.getServerPublicKeyData(),
            isakmpHeader.initiatorCookie, isakmpHeader.responderCookie, saPayloadBody, idPayloadBody};
        byte[] dataForHash = Utils.combineData(dataArray);

        return mAlgorithmUtil.hashDataWithKey(mKeyExchangeUtil.getSKEYID(), dataForHash);
    }

    private byte[] prepareMainMode1stEncryptedPayload(byte[] payloadData) {
        try {
            byte[] initiatorPublicKey = mKeyExchangeUtil.getPublicKey();
            // first encrypted message using the IV from initiator's and responder's public keys
            byte[][] dataArray = {mKeyExchangeUtil.getPublicKey(), mKeyExchangeUtil.getServerPublicKeyData()};
            byte[] data = Utils.combineData(dataArray);

            byte[] ivBytes = mAlgorithmUtil.hashData(data);
            byte[] first16Bytes = new byte[AlgorithmUtil.AES_BLOCK_SIZE];
            if (ivBytes != null) {
                System.arraycopy(ivBytes, 0, first16Bytes, 0, AlgorithmUtil.AES_BLOCK_SIZE);
            }
            mAlgorithmUtil.setIv(first16Bytes);

            byte[] output = mAlgorithmUtil.aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), payloadData);

//            print("Encrypted data", output);

            return output;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] getNonESPMarker() {
        byte[] nonESPMarker = new byte[NON_ESP_MARKER_LENGTH];

        return nonESPMarker;
    }

    private byte[] prependNonESPMarker(byte[] msg) {
        // prepend the non-esp marker which is 4 zero bytes when sending messages to 4500. RFC3947, RFC3948
        byte[] msgWithPrependHeader = new byte[NON_ESP_MARKER_LENGTH + msg.length];
        System.arraycopy(msg, 0, msgWithPrependHeader, NON_ESP_MARKER_LENGTH, msg.length);

        return msgWithPrependHeader;
    }

    private byte[] prepareLoginConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14/*login attribute payload*/, 1);
        byte[] reserve = new byte[1];

        byte[] loginAttributePayload = prepareLoginAttributePayload();
        byte[][] payloads = new byte[1][];
        payloads[0] = loginAttributePayload;
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);

        byte[][] dataArray = {nextPayload, reserve, payloadLength, hashData, loginAttributePayload};
        byte[] payloadBeforeEncrypt = Utils.combineData(dataArray);

        return AlgorithmUtil.getInstance().aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), payloadBeforeEncrypt);
    }

    private byte[] prepareLoginAttributePayload() {
        byte[] nextPayload = new byte[1];   // 0 - None (no more)
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(2, 1);      // ISKAMP_CFG_REPLY
        byte[] identifier = new byte[2];

        try {
            // XAUTH-USER-NAME. https://tools.ietf.org/html/draft-beaulieu-ike-xauth-02
            byte[] attribute_username = getTypeLengthValueAttribute(16521, mUserName.getBytes("UTF-8"));
            // // XAUTH-USER-PASSWORD
            byte[] attribute_password = getTypeLengthValueAttribute(16522, mPassword.getBytes("UTF-8"));
            int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                    type.length + identifier.length + attribute_username.length + attribute_password.length;
            byte[] payloadLength = Utils.toBytes(length, 2);
            byte[][] dataArray = {nextPayload, reserve, payloadLength, type, reserve, identifier, attribute_username, attribute_password};
            byte[] payload = Utils.combineData(dataArray);

            return payload;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] generateHashDataForPayload(byte[] messageId, byte[] payload) {
        byte[][] dataArray = {messageId, payload};
        byte[] inputData = Utils.combineData(dataArray);

        return hashPhase2Payload(inputData);
    }

    public byte[] generateHashDataForPayloads(byte[] messageId, byte[][] payloads){

        byte[] payloadData = Utils.combineData(payloads);
        byte[][] dataArray = {messageId, payloadData};
        byte[] inputData = Utils.combineData(dataArray);

        return hashPhase2Payload(inputData);
    }

    private byte[] hashPhase2Payload(byte[] data) {
        return mAlgorithmUtil.hashDataWithKey(mKeyExchangeUtil.getSKEYIDa(), data);
    }

    private byte[] getTypeLengthValueAttribute(int type, byte[] attribute_data) {
        byte[] attribute_type = Utils.toBytes(type, 2);
        byte[] attribute_length = Utils.toBytes(attribute_data.length, 2);

        byte[][] dataArray = {attribute_type, attribute_length, attribute_data};
        byte[] output = Utils.combineData(dataArray);
        return output;
    }

    private byte[] getTypeValueAttribute(int type, int value) {
        byte[] attribute_type = Utils.toBytes(type, 2);
        byte[] output = new byte[4];
        byte[] attribute_value = Utils.toBytes(value, 2);
        System.arraycopy(attribute_type, 0, output, 0, attribute_type.length);
        System.arraycopy(attribute_value, 0, output, attribute_type.length, attribute_value.length);

        return output;
    }

    private byte[] prepareAcknowledgeConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14/*login config payload*/, 1);
        byte[] reserve = new byte[1];

        byte[] ackAttributePayload = prepareAckAttributePayload();
        byte[][] payloads = new byte[1][];
        payloads[0] = ackAttributePayload;
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);

        byte[][] dataArray = {nextPayload, reserve, payloadLength, hashData, ackAttributePayload};
        byte[] payloadBeforeEncrypt = Utils.combineData(dataArray);

        return AlgorithmUtil.getInstance().aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), payloadBeforeEncrypt);
    }

    private byte[] prepareAckAttributePayload() {
        byte[] nextPayload = new byte[1];   // 0 - None (no more)
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(4, 1);      // ISAKMP-CFG-ACK
        byte[] identifier = new byte[2];

        // 49295 (0xc08f)
        byte[] attribute = Utils.toBytes(49295, 2);
        byte[] attribute_value = new byte[2];
        int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                type.length + identifier.length + attribute.length + attribute_value.length;
        byte[] payloadLength = Utils.toBytes(length, 2);

        byte[][] dataArray = {nextPayload, reserve, payloadLength, type, reserve, identifier, attribute, attribute_value};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    /**
     * Generates the new IV base on the last IV and message id
     * https://tools.ietf.org/id/draft-ietf-ipsec-ike-01.txt, section 4.2
     *
     */
    public void preparePhase2IV(byte[] messageId) {
        byte[] phase1FirstIv = mAlgorithmUtil.getPhase1FirstIv();
        byte[] currentIv = mAlgorithmUtil.getIv();
        if (phase1FirstIv == null || currentIv == null) {
            return;
        }

        byte[][] dataArray = {phase1FirstIv, messageId};
        byte[] data = Utils.combineData(dataArray);

        byte[] ivBytes = mAlgorithmUtil.hashData(data);
        if (ivBytes != null) {
            byte[] first16Bytes = new byte[AlgorithmUtil.AES_BLOCK_SIZE];
            System.arraycopy(ivBytes, 0, first16Bytes, 0, AlgorithmUtil.AES_BLOCK_SIZE);
            mAlgorithmUtil.setIv(first16Bytes);

            print("Phase2 IV", first16Bytes);
        }
    }

    private byte[] prepareIpConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14, 1);
        byte[] reserve = new byte[1];

        byte[] ipRequestAttributePayload = prepareIpRequestAttributePayload();
        byte[][] payloads = {ipRequestAttributePayload};
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);

        byte[][] dataArray = {nextPayload, reserve, payloadLength, hashData, ipRequestAttributePayload};
        byte[] payloadBeforeEncrypt = Utils.combineData(dataArray);

        return AlgorithmUtil.getInstance().aesEncryptData(mKeyExchangeUtil.getSKEYIDe(), payloadBeforeEncrypt);
    }

    public byte[] prepareIpRequestAttributePayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserve = new byte[1];
        byte[] type = Utils.toBytes(1, 1);      // ISAKMP_CFG_REQUEST
        byte[] identifier = Utils.toBytes(28062, 2);

        try {
            byte[] ip4_address = getTypeValueAttribute(1, 0);
            byte[] ip4_netmask = getTypeValueAttribute(2, 0);
            byte[] ip4_dns = getTypeValueAttribute(3, 0);
            byte[] ip4_nbns = getTypeValueAttribute(4, 0);

            int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                    type.length + identifier.length + ip4_address.length + ip4_netmask.length
                    + ip4_dns.length + ip4_nbns.length;
            byte[] payloadLength = Utils.toBytes(length, 2);
            byte[][] dataArray = {nextPayload, reserve, payloadLength, type, reserve, identifier, ip4_address,
                    ip4_netmask, ip4_dns, ip4_nbns};
            byte[] payload = Utils.combineData(dataArray);

            return payload;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] preparePhase2SAPayload() {
        byte[] nextPayload = Utils.toBytes(10, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] doi = Utils.toBytes(1);
        byte[] situation = Utils.toBytes(1);        // SIT_IDENTITY_ONLY

        byte[] proposalPayload = preparePhase2ProposalPayload();
        int length = nextPayload.length + reserved.length + 2 /*payloadLength */ + doi.length + situation.length + proposalPayload.length;
        byte[] payloadLength = Utils.toBytes(length, 2);
        byte[][] dataArray = {nextPayload, reserved, payloadLength, doi, situation, proposalPayload};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] preparePhase2ProposalPayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(3, 1);        // PROTO_IPSEC_ESP
        byte[] spiSize = Utils.toBytes(4, 1);
        byte[] transformNumber = Utils.toBytes(12, 1);
        byte[] spi = mKeyExchangeUtil.getInboundSPI();

        byte[] transformPayload1 = preparePhase2TransformPayload(1, 3, 12);
        byte[] transformPayload2 = preparePhase2TransformPayload(2, 3, 12);
        byte[] transformPayload3 = preparePhase2TransformPayload(3, 3, 12);
        byte[] transformPayload4 = preparePhase2TransformPayload(4, 3, 12);
        byte[] transformPayload5 = preparePhase2TransformPayload(5, 3, 12);
        byte[] transformPayload6 = preparePhase2TransformPayload(6, 3, 12);
        byte[] transformPayload7 = preparePhase2TransformPayload(7, 3, 3);
        byte[] transformPayload8 = preparePhase2TransformPayload(8, 3, 3);
        byte[] transformPayload9 = preparePhase2TransformPayload(9, 3, 3);
        byte[] transformPayload10 = preparePhase2TransformPayload(10, 3, 2);
        byte[] transformPayload11 = preparePhase2TransformPayload(11, 3, 2);
        byte[] transformPayload12 = preparePhase2TransformPayload(12, 0, 2);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + spi.length + transformPayload1.length +
                transformPayload2.length + transformPayload3.length + transformPayload4.length + transformPayload5.length +
                transformPayload6.length + transformPayload7.length + transformPayload8.length + transformPayload9.length +
                transformPayload10.length + transformPayload11.length + transformPayload12.length;

        byte[] payloadLength = Utils.toBytes(size, 2);
        byte[][] dataArray = {nextPayload, reserved, payloadLength, proposalNumber, protocolId, spiSize, transformNumber,
                spi, transformPayload1, transformPayload2, transformPayload3, transformPayload4, transformPayload5,
                transformPayload6, transformPayload7, transformPayload8, transformPayload9, transformPayload10,
                transformPayload11, transformPayload12};

        byte[] proposalPayload = Utils.combineData(dataArray);

        return proposalPayload;
    }

    private byte[] preparePhase2TransformPayload(int transformNumber, int nextPayloadNum, int transID) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNum, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] transformNum = Utils.toBytes(transformNumber, 1);
        byte[] transformID = Utils.toBytes(transID, 1);
        byte[] reserved2 = new byte[2];

        byte[] attributes = prepareDOIAttribute1(transformNumber);

        int length = nextPayload.length + reserved.length + 2/*payloadLength*/ + transformNum.length
                + transformID.length + reserved2.length + attributes.length;
        byte[] payloadLength = Utils.toBytes(length, 2);
        byte[][] dataArray = {nextPayload, reserved, payloadLength, transformNum, transformID, reserved2, attributes};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private byte[] prepareDOIAttribute1(int transformNumber) {
        byte[] attributes = null;

        switch (transformNumber) {
            case 1:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 5), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 256), 0, attributes, 16, 4);
                break;

            case 2:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 2), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 256), 0, attributes, 16, 4);
                break;

            case 3:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 1), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 256), 0, attributes, 16, 4);
                break;

            case 4:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 5), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 128), 0, attributes, 16, 4);
                break;

            case 5:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 2), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 128), 0, attributes, 16, 4);
                break;

            case 6:
                attributes = new byte[20];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 1), 0, attributes, 12, 4);
                System.arraycopy(prepareDOIAttribute2(6, 128), 0, attributes, 16, 4);
                break;

            case 7:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 5), 0, attributes, 12, 4);
                break;

            case 8:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 2), 0, attributes, 12, 4);
                break;

            case 9:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 1), 0, attributes, 12, 4);
                break;

            case 10:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 5), 0, attributes, 12, 4);
                break;

            case 11:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 2), 0, attributes, 12, 4);
                break;

            case 12:
                attributes = new byte[16];
                System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
                System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
                System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
                System.arraycopy(prepareDOIAttribute2(5, 1), 0, attributes, 12, 4);
                break;

            default:
                break;
        }

        return attributes;
    }

    private byte[] prepareDOIAttribute2(int type, int value) {
        byte[] attributeType = null;
        byte[] attributeValue = null;
        byte[] output = null;

        switch (type) {
            case 1: // SA_LIFE_TYPE and Seconds
                attributeType = Utils.toBytes(0x8001, 2);
                attributeValue = Utils.toBytes(value, 2);
                break;

            case 2: // SA_LIFE_DURATION
                attributeType = Utils.toBytes(0x8002, 2);
                attributeValue = Utils.toBytes(value, 2);
                break;

            case 4: // ENCAPSULATION_MODE. ENCAPSULATION_MODE_UDP_TUNNEL_RFC
                attributeType = Utils.toBytes(0x8004, 2);
                attributeValue = Utils.toBytes(value, 2);
                break;

            case 5: // AUTH_ALGORITHM. AUTH_ALGORITHM_HMAC_SHA2_256
                attributeType = Utils.toBytes(0x8005, 2);
                attributeValue = Utils.toBytes(value, 2);
                break;

            case 6: // KEY_LENGTH.
                attributeType = Utils.toBytes(0x8006, 2);
                attributeValue = Utils.toBytes(value, 2);
                break;

            default:
                break;
        }

        if (attributeType == null || attributeValue == null) {
            return output;
        }

        byte[][] dataArray = {attributeType, attributeValue};
        output = Utils.combineData(dataArray);

        return output;
    }

    /**
     * First ID payload for IPV4_Address
     * @param ipAddress
     * @return
     */
    private byte[] preparePhase2IDPayload1(byte[] ipAddress) {
        byte[] nextPayload = Utils.toBytes(5, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(1, 1);  // IPV4_ADDRESS
        byte[] protocolId = new byte[1];        // 0
        byte[] port = new byte[2];              // 0

        byte[] data = new byte[4];
        System.arraycopy(ipAddress, 0, data, 0, data.length);

        int length = nextPayload.length + reserved.length + 2 /*payloadLength*/ +
                type.length + protocolId.length + port.length + data.length;
        byte[] payloadLength = Utils.toBytes(length, 2);

        byte[][] dataArray = {nextPayload, reserved, payloadLength, type, protocolId, port, data};
        byte[] payload = Utils.combineData(dataArray);

        return payload;

    }

    /**
     * Second ID payload for IPV4_Address_Subnet
     * @param subnet
     * @return
     */
    private byte[] preparePhase2IDPayload2(byte[] subnet) {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(4, 1);  // IPV4_ADDRESS_SUBNET
        byte[] protocolId = new byte[1];        // 0
        byte[] port = new byte[2];              // 0

        byte[] data = new byte[8];
        System.arraycopy(subnet, 0, data, 0, subnet.length);

        int length = nextPayload.length + reserved.length + 2 /*payloadLength*/ +
                type.length + protocolId.length + port.length + data.length;

        byte[] payloadLength = Utils.toBytes(length, 2);
        byte[][] dataArray = {nextPayload, reserved, payloadLength, type, protocolId, port, data};
        byte[] payload = Utils.combineData(dataArray);

        return payload;

    }

    private byte[] prepareHashPayload(byte[] hashData, int nextPayloadNum) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNum, 1);
        byte[] reserved = new byte[1];

        int len = nextPayload.length + reserved.length + 2 /*payloadLength*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(len, 2);
        byte[][] dataArray = {nextPayload, reserved, payloadLength, hashData};
        byte[] payload = Utils.combineData(dataArray);

        return payload;
    }

    private void print(String label, byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : data) {
            stringBuilder.append(String.format("%02x ", b));
        }

        Log.i(TAG, "**** [" + label + "] length: " + data.length + ", " + stringBuilder.toString());
    }

    private byte[] genereateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }

}
